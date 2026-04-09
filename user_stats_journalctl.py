#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple


def parse_iso_ts(ts: str) -> datetime:
    # Example: 2026-01-15T09:36:39.843Z
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def parse_journal_ts_us(ts_us: str) -> Optional[datetime]:
    # journalctl JSON uses microseconds since Unix epoch for __REALTIME_TIMESTAMP
    try:
        microseconds = int(ts_us)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc)


def extract_message_payload(journal_obj: dict) -> Optional[dict]:
    msg = journal_obj.get("MESSAGE")

    if isinstance(msg, dict):
        return msg

    if isinstance(msg, str):
        try:
            parsed = json.loads(msg)
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, dict):
            return parsed

    return None


def payload_timestamp(payload: dict, journal_obj: dict) -> Optional[datetime]:
    ts_raw = payload.get("timestamp")
    if isinstance(ts_raw, str) and ts_raw:
        try:
            return parse_iso_ts(ts_raw)
        except ValueError:
            pass

    jt = journal_obj.get("__REALTIME_TIMESTAMP")
    return parse_journal_ts_us(jt) if isinstance(jt, str) else None


def is_request(payload: dict) -> bool:
    return payload.get("messageType") == "request"


def extract_user(payload: dict) -> Optional[str]:
    user = payload.get("user")
    if not isinstance(user, dict):
        return None

    username = user.get("username")
    return username if isinstance(username, str) and username else None


def normalize_path(payload: dict) -> str:
    path = payload.get("request", {}).get("url", {}).get("path")
    return path if isinstance(path, str) else ""


def require_dir(path_str: str, what: str) -> Path:
    p = Path(path_str)
    if not p.is_dir():
        raise FileNotFoundError(f"{what} not found: {p}")
    return p


def resolve_source(source: str, journal_dir: Optional[str]) -> Tuple[str, Optional[Path]]:
    if source not in {"auto", "production", "techsupport"}:
        raise ValueError(f"Invalid source: {source}")

    if source == "production":
        return source, None

    if source == "techsupport":
        if not journal_dir:
            raise FileNotFoundError(
                "Techsupport source selected but --journal-dir was not provided."
            )
        return source, require_dir(journal_dir, "Techsupport journal directory")

    # auto mode: use techsupport only if --journal-dir is explicitly provided
    if journal_dir:
        return "techsupport", require_dir(journal_dir, "Techsupport journal directory")

    return "production", None


def build_journalctl_cmd(
    source: str,
    namespace: str,
    since: str,
    until: Optional[str],
    unit: Optional[str],
    journal_dir: Optional[Path],
) -> List[str]:
    cmd = [
        "journalctl",
        "--no-pager",
        "-o",
        "json",
        "--since",
        since,
    ]

    if until:
        cmd.extend(["--until", until])

    if source == "production":
        if namespace:
            cmd.append(f"--namespace={namespace}")
    else:
        if journal_dir is None:
            raise ValueError("journal_dir is required for techsupport source")
        cmd.append(f"--directory={journal_dir}")
        if namespace:
            cmd.append(f"_NAMESPACE={namespace}")

    if unit:
        cmd.extend(["-u", unit])

    return cmd


def iter_journal_objects(cmd: List[str]) -> Iterator[dict]:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj

    stderr_text = ""
    if proc.stderr is not None:
        stderr_text = proc.stderr.read().strip()

    rc = proc.wait()
    if rc != 0:
        raise RuntimeError(f"journalctl failed with exit code {rc}: {stderr_text}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Extract per-username session starts from IP Fabric logs in journalctl."
    )
    ap.add_argument(
        "--source",
        choices=["auto", "production", "techsupport"],
        default="auto",
        help=(
            "Log source mode. "
            "auto: use --journal-dir if provided, else auto-detect techsupport dir, else production journal. "
            "production: use system journal. techsupport: use --directory journal files."
        ),
    )
    ap.add_argument(
        "--journal-dir",
        type=str,
        default=None,
        help=(
            "Path to techsupport journal directory, e.g. "
            "/home/autoboss/techsupport/techsupport-xxxxxxx/system-log/journal"
        ),
    )
    ap.add_argument(
        "--namespace",
        type=str,
        default="ipf-api",
        help="journalctl namespace (default: ipf-api)",
    )
    ap.add_argument(
        "--unit",
        type=str,
        default=None,
        help="Optional systemd unit filter, e.g. ipf-api.service",
    )
    ap.add_argument(
        "--since",
        type=str,
        default="1 month ago",
        help='journalctl --since value (default: "1 month ago")',
    )
    ap.add_argument(
        "--until",
        type=str,
        default=None,
        help="Optional journalctl --until value",
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
        "--basic-summary",
        type=str,
        default="user_basic_summary.csv",
        help="Output CSV with basic user stats (default: user_basic_summary.csv).",
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
        resolved_source, resolved_journal_dir = resolve_source(args.source, args.journal_dir)
    except (FileNotFoundError, ValueError) as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    cmd = build_journalctl_cmd(
        source=resolved_source,
        namespace=args.namespace,
        since=args.since,
        until=args.until,
        unit=args.unit,
        journal_dir=resolved_journal_dir,
    )

    events: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
    per_user_calls = Counter()
    per_user_endpoints: Dict[str, Set[str]] = defaultdict(set)
    per_user_days: Dict[str, Set[str]] = defaultdict(set)
    per_user_first_request: Dict[str, datetime] = {}
    per_user_last_request: Dict[str, datetime] = {}

    total_journal_rows = 0
    parsed_payload_rows = 0
    total_user_entries = 0
    excluded_entries = 0

    try:
        for journal_obj in iter_journal_objects(cmd):
            total_journal_rows += 1

            payload = extract_message_payload(journal_obj)
            if payload is None:
                continue
            parsed_payload_rows += 1

            if not is_request(payload):
                continue

            ts = payload_timestamp(payload, journal_obj)
            if ts is None:
                continue

            user = extract_user(payload)
            if not user:
                continue

            path = normalize_path(payload)
            if any(excl in path for excl in args.exclude_path):
                excluded_entries += 1
                continue

            events[user].append((ts, path))
            total_user_entries += 1

            endpoint = path if path else "unknown"
            day = ts.date().isoformat()
            per_user_calls[user] += 1
            per_user_endpoints[user].add(endpoint)
            per_user_days[user].add(day)
            per_user_first_request[user] = min(per_user_first_request.get(user, ts), ts)
            per_user_last_request[user] = max(per_user_last_request.get(user, ts), ts)
    except RuntimeError as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    idle_s = float(args.idle)
    out_path = Path(args.out)
    basic_summary_path = Path(args.basic_summary)

    total_sessions = 0

    with out_path.open("w", encoding="utf-8") as out_f:
        for user, evts in events.items():
            evts.sort(key=lambda x: x[0])

            session_start: Optional[datetime] = None
            session_end: Optional[datetime] = None
            first_path: Optional[str] = None
            last_path: Optional[str] = None
            session_requests = 0
            session_endpoints: Set[str] = set()

            def flush_session() -> None:
                nonlocal session_start, session_end, first_path, last_path, session_requests, session_endpoints
                nonlocal total_sessions

                if session_start is None or session_end is None:
                    return

                duration_s = (session_end - session_start).total_seconds()
                record = {
                    "username": user,
                    "session_start_ts": session_start.isoformat(),
                    "session_end_ts": session_end.isoformat(),
                    "session_duration_seconds": duration_s,
                    "session_request_count": session_requests,
                    "session_unique_endpoints": len(session_endpoints),
                }
                if args.include_path:
                    record["first_path"] = first_path or "unknown"
                    record["last_path"] = last_path or "unknown"

                out_f.write(json.dumps(record) + "\n")

                total_sessions += 1

            prev_ts: Optional[datetime] = None
            for ts, path in evts:
                endpoint = path or "unknown"
                new_session = prev_ts is None or (ts - prev_ts).total_seconds() > idle_s
                if new_session:
                    flush_session()
                    session_start = ts
                    session_end = ts
                    first_path = endpoint
                    last_path = endpoint
                    session_requests = 1
                    session_endpoints = {endpoint}
                else:
                    session_end = ts
                    last_path = endpoint
                    session_requests += 1
                    session_endpoints.add(endpoint)

                prev_ts = ts

            flush_session()

    with basic_summary_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["username", "calls", "unique_endpoints", "active_days", "first_request_utc", "last_request_utc"])
        for user, calls in per_user_calls.most_common():
            w.writerow(
                [
                    user,
                    calls,
                    len(per_user_endpoints[user]),
                    len(per_user_days[user]),
                    per_user_first_request[user].isoformat(),
                    per_user_last_request[user].isoformat(),
                ]
            )

    print("Journal source:")
    print(f" - mode: {resolved_source}")
    if resolved_journal_dir is not None:
        print(f" - directory: {resolved_journal_dir}")
    print(f" - command: {' '.join(cmd)}")
    print(f"Journal rows scanned: {total_journal_rows}")
    print(f"Rows with JSON payload in MESSAGE: {parsed_payload_rows}")
    print(f"Users found: {len(per_user_calls)}")
    print(f"Total sessions: {total_sessions}")
    print(f"User-attributed requests processed: {total_user_entries} (excluded: {excluded_entries})")
    print(f"Wrote sessions: {out_path}")
    print(f"Wrote basic summary: {basic_summary_path}")


if __name__ == "__main__":
    main()
