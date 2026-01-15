#!/usr/bin/env python3
import argparse
import csv
import gzip
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple


DEFAULT_FOLDERS = [
    Path("/var/log/ipf/ipf-api/"),
    Path("/var/log/nimpee/"),
]


def parse_ts(ts: str) -> datetime:
    # e.g. "2026-01-15T09:36:39.843Z"
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def open_maybe_gz(path: Path):
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def iter_log_files(folder: Path) -> Iterable[Path]:
    # Scan all api.log* files in the folder
    files = sorted(folder.glob("api.log*"))
    return [p for p in files if p.is_file()]


def iter_entries(path: Path) -> Iterator[dict]:
    with open_maybe_gz(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(" : ", 1)
            if len(parts) != 2:
                continue
            try:
                data = json.loads(parts[1])
                if isinstance(data, dict):
                    yield data
            except json.JSONDecodeError:
                continue


def normalize_path(data: dict) -> str:
    p = data.get("request", {}).get("url", {}).get("path")
    return p if isinstance(p, str) else ""


def extract_user(data: dict) -> Optional[str]:
    user = data.get("user", {})
    if not isinstance(user, dict):
        return None
    u = user.get("username")
    return u if isinstance(u, str) and u else None


def is_request(data: dict) -> bool:
    return data.get("messageType") == "request"


def resolve_folders(cli_folders: List[str]) -> List[Path]:
    """
    - If user provides folders: use all of them (must exist).
    - If user provides none: use all existing DEFAULT_FOLDERS (not OR; we take every one that exists).
    """
    folders: List[Path] = []

    if cli_folders:
        for s in cli_folders:
            p = Path(s)
            if not (p.exists() and p.is_dir()):
                raise FileNotFoundError(f"Folder not found or not a directory: {p}")
            folders.append(p)
    else:
        folders.extend(p for p in DEFAULT_FOLDERS if p.exists() and p.is_dir())
        if not folders:
            tried = ", ".join(str(p) for p in DEFAULT_FOLDERS)
            raise FileNotFoundError(f"No default log folder found. Tried: {tried}")

    # de-dup while preserving order
    seen = set()
    uniq: List[Path] = []
    for p in folders:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


def main():
    ap = argparse.ArgumentParser(
        description="Extract per-username session starts from IP Fabric api.log* files (IP ignored)."
    )

    # allow 0, 1, or many folders
    ap.add_argument(
        "folders",
        nargs="*",
        help=(
            "One or more folders containing api.log* / api.log*.gz. "
            "If omitted, tries BOTH /var/log/ipf/ipf-api/ and /var/log/nimpee/ (whichever exist)."
        ),
    )

    ap.add_argument(
        "--idle",
        type=float,
        default=30 * 60,
        help="Idle gap in seconds that starts a new session (default: 1800 = 30min).",
    )
    ap.add_argument(
        "--out",
        type=str,
        default="user_sessions.jsonl",
        help="Output JSONL of session starts (default: user_sessions.jsonl).",
    )
    ap.add_argument(
        "--summary",
        type=str,
        default="user_sessions_summary.csv",
        help="Output CSV summary (default: user_sessions_summary.csv).",
    )
    ap.add_argument(
        "--include-path",
        action="store_true",
        help="Include first request path of the session in outputs.",
    )
    ap.add_argument(
        "--exclude-path",
        action="append",
        default=["/analytics/snowplow"],
        help="Exclude requests whose path contains this string. Repeatable. Default: /analytics/snowplow",
    )

    args = ap.parse_args()

    try:
        folders = resolve_folders(args.folders)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    idle_s = float(args.idle)
    out_path = Path(args.out)
    summary_path = Path(args.summary)

    # Collect per-user events (timestamp, path) across ALL folders
    events: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)

    total_entries_seen = 0
    total_user_entries = 0
    excluded_entries = 0
    total_files = 0

    for folder in folders:
        for log_file in iter_log_files(folder):
            total_files += 1
            for data in iter_entries(log_file):
                total_entries_seen += 1

                if not is_request(data):
                    continue

                ts_raw = data.get("timestamp")
                if not ts_raw:
                    continue
                try:
                    ts = parse_ts(ts_raw)
                except Exception:
                    continue

                user = extract_user(data)
                if not user:
                    continue

                path = normalize_path(data)
                if any(excl in path for excl in args.exclude_path):
                    excluded_entries += 1
                    continue

                events[user].append((ts, path))
                total_user_entries += 1

    # Sessionize and write outputs
    per_user_session_count = Counter()
    first_session: Dict[str, datetime] = {}
    last_session: Dict[str, datetime] = {}
    total_sessions = 0

    with out_path.open("w", encoding="utf-8") as out_f:
        for user, evts in events.items():
            evts.sort(key=lambda x: x[0])

            prev_ts: Optional[datetime] = None
            for ts, path in evts:
                new_session = prev_ts is None or (ts - prev_ts).total_seconds() > idle_s
                if new_session:
                    record = {
                        "username": user,
                        "session_start_ts": ts.isoformat(),
                    }
                    if args.include_path:
                        record["first_path"] = path
                    out_f.write(json.dumps(record) + "\n")

                    per_user_session_count[user] += 1
                    total_sessions += 1
                    first_session[user] = min(first_session.get(user, ts), ts)
                    last_session[user] = max(last_session.get(user, ts), ts)

                prev_ts = ts

    # Summary CSV (merged naturally by username: counts add up, oldest/newest computed from all data)
    with summary_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["username", "session_count", "first_session_start_utc", "last_session_start_utc"])
        for user, cnt in per_user_session_count.most_common():
            w.writerow([user, cnt, first_session[user].isoformat(), last_session[user].isoformat()])

    total_users = len(per_user_session_count)

    print("Logs folders used:")
    for p in folders:
        print(f" - {p}")
    print(f"Log files scanned: {total_files}")
    print(f"Users found: {total_users}")
    print(f"Total sessions: {total_sessions}")
    print(f"User-attributed requests processed: {total_user_entries} (excluded: {excluded_entries})")
    print(f"Wrote sessions: {out_path}")
    print(f"Wrote summary: {summary_path}")


if __name__ == "__main__":
    main()
