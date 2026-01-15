# IP Fabric User Sessions Analysis

This script reads IP Fabric API log files (`api.log*` / `api.log*.gz`) and computes
per-user session statistics.

## What it produces

- `user_sessions.jsonl`: one line per detected session (username, session start;
  optionally the first request path).
- `user_sessions_summary.csv`: per-username session counts and first/last
  session start timestamps.

## Basic usage

SCP, or copy/paste the content of the file `user_stats_6.10_7.3.py` into the IP Fabric instance, for example in the home folder of the `osadmin` user.

Then run the script with:

```bash
sudo python3 user_stats_6.10_7.3.py
```

## Log locations

By default it looks for logs in these folders if they exist:

- `/var/log/ipf/ipf-api/`
- `/var/log/nimpee/`

You will need to run the script with `sudo` to read these logs.

## Extra options

- `--idle SECONDS`     idle gap that starts a new session (default: 1800).
- `--out PATH`         output JSONL file (default: `user_sessions.jsonl`).
- `--summary PATH`     output CSV file (default: `user_sessions_summary.csv`).
- `--include-path`     include first request path of the session in JSONL.
- `--exclude-path X`   exclude requests whose path contains X
                       (repeatable, default: `/analytics/snowplow`).

## Tests

The file `user_stats_6.10_7.3.py` has been tested with IP Fabric version `6.10` up to `7.3`. From version `7.5` the logs format has changed and this script may not provide accurate results.

## Internal details

*For internal use only* if you need to provide a specific folder:

```bash
python3 user_stats_6.10_7.3.py /var/log/ipf/ipf-api/ /var/log/nimpee/
```
