# IP Fabric User Sessions Analysis

Two scripts are available depending on the IP Fabric version you are targeting.

| Script | IP Fabric version | Log source |
|---|---|---|
| `user_stats_6.10_7.3.py` | 6.10 – 7.3 | `api.log*` files in `/var/log/` |
| `user_stats_7.9+.py` | 7.9+ | `journalctl` (live system or local journal directory) |

> **Note:** IP Fabric migrated its API logs to `journalctl` in **v7.9**. `user_stats_7.9+.py` has been tested on **7.10**.

---

## `user_stats_7.9+.py` (7.9+)

### What it produces

- **`user_sessions.jsonl`** — one record per detected session:
  - `username`
  - `session_start_ts` / `session_end_ts`
  - `session_duration_seconds`
  - `session_request_count`
  - `session_unique_endpoints`
  - `first_path` / `last_path` *(only when `--include-path` is set)*

- **`user_basic_summary.csv`** — one row per user, sorted by total calls:
  - `username`, `calls`, `unique_endpoints`, `active_days`, `first_request_utc`, `last_request_utc`

### Log source

By default the script reads from the live system journal. Pass `--journal-dir` to point it at a local journal directory instead.

### Basic usage

Copy/paste or SCP `user_stats_7.9+.py` onto the IP Fabric appliance (e.g. `~osadmin/`) and run:

```bash
# Production — reads last month of logs by default
python3 'user_stats_7.9+.py'

# Explicit time window
python3 'user_stats_7.9+.py' --since "7 days ago" --until "now"

# Include first/last request path per session
python3 'user_stats_7.9+.py' --include-path
```

> **Internal use only:** to read from a local journal directory, pass `--journal-dir`:
> ```bash
> python3 'user_stats_7.9+.py' \
>   --journal-dir /path/to/system-log/journal
> ```

### All options

| Option | Default | Description |
| --- | --- | --- |
| `--journal-dir PATH` | *(none)* | Read from a local journal directory instead of the live journal |
| `--namespace` | `ipf-api` | journalctl namespace |
| `--unit` | *(none)* | Optional systemd unit filter, e.g. `ipf-api.service` |
| `--since` | `1 month ago` | journalctl `--since` value |
| `--until` | *(none)* | journalctl `--until` value |
| `--idle SECONDS` | `1800` | Idle gap in seconds that starts a new session |
| `--out PATH` | `user_sessions.jsonl` | Output JSONL file |
| `--basic-summary PATH` | `user_basic_summary.csv` | Output CSV file |
| `--include-path` | *(off)* | Add `first_path`/`last_path` fields to JSONL |
| `--exclude-path X` | `/analytics/snowplow` | Exclude requests whose path contains X (repeatable) |

---

## `user_stats_6.10_7.3.py` (6.10 – 7.3)

Reads `api.log*` / `api.log*.gz` files directly from disk.

### Basic usage

```bash
sudo python3 user_stats_6.10_7.3.py
```

Default log folders (whichever exist):

- `/var/log/ipf/ipf-api/`
- `/var/log/nimpee/`

Run with `sudo` to access these log files.

### Extra options

- `--idle SECONDS`    idle gap that starts a new session (default: 1800).
- `--out PATH`        output JSONL file (default: `user_sessions.jsonl`).
- `--summary PATH`    output CSV file (default: `user_sessions_summary.csv`).
- `--include-path`    include first request path of the session in JSONL.
- `--exclude-path X`  exclude requests whose path contains X (repeatable, default: `/analytics/snowplow`).

Provide explicit folders as positional arguments if needed:

```bash
python3 user_stats_6.10_7.3.py /var/log/ipf/ipf-api/ /var/log/nimpee/
```
