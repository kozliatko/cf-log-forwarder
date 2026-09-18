#!/usr/bin/env python3
"""
Demo script: downloads AUDIT LOGS from Cloudflare (read-only) and prints
them to the console.

- Uses the Audit Logs v2 API: GET /accounts/{account_id}/audit_logs_v2
- GET requests only; nothing is modified or persisted.
- Supports cursor-based pagination (fetches all pages).

Usage:
    python3 cf_audit_demo.py
    python3 cf_audit_demo.py --since 2026-09-16T00:00:00Z --before 2026-09-18T00:00:00Z
    python3 cf_audit_demo.py --json          # full JSON for every record
    python3 cf_audit_demo.py --action login  # filter by action type
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Error: missing the 'requests' library. Install it with: pip install requests")

# =====================================================================
# Configuration
# =====================================================================
# Credentials are read from a .env file next to the script or from the
# CF_API_TOKEN / CF_ACCOUNT_ID environment variables (env takes priority).
SCRIPT_DIR = Path(__file__).resolve().parent
ENV_FILE = SCRIPT_DIR / ".env"


def parse_env_file(path: Path) -> dict[str, str]:
    """Simple .env file parser (no python-dotenv dependency)."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not (value.startswith('"') or value.startswith("'")):
            value = value.split("#")[0].strip()
        if key:
            values[key] = value
    return values


_ENV = parse_env_file(ENV_FILE)
API_TOKEN, ACCOUNT_ID = load_credentials = (None, None)  # placeholder, set below


def load_credentials() -> tuple[str, str]:
    """Read the API token and Account ID from env vars or the .env file."""
    token = os.environ.get("CF_API_TOKEN") or _ENV.get("CF_API_TOKEN", "")
    account = os.environ.get("CF_ACCOUNT_ID") or _ENV.get("CF_ACCOUNT_ID", "")
    return token, account


API_TOKEN, ACCOUNT_ID = load_credentials()


def cfg_int(name: str, default: int) -> int:
    """Integer config from env vars (priority) or the .env file."""
    raw = os.environ.get(name) or _ENV.get(name, "")
    try:
        return int(raw) if raw else default
    except ValueError:
        return default
# =====================================================================

API_BASE = "https://api.cloudflare.com/client/v4"

# Default time range: last 24 hours
DEFAULT_LOOKBACK_HOURS = cfg_int("DEFAULT_LOOKBACK_HOURS", 24)

# Records per page (API limit)
PAGE_LIMIT = cfg_int("AUDIT_PAGE_LIMIT", 100)


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def build_session() -> requests.Session:
    """Session with auth headers - read-only access."""
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": "cf-audit-demo/1.0",
        }
    )
    return s


def fetch_audit_logs(
    session: requests.Session,
    since: str,
    before: str,
    action_type: str | None = None,
) -> list[dict]:
    """Fetch all audit logs in the given time range (paginated)."""
    url = f"{API_BASE}/accounts/{ACCOUNT_ID}/audit_logs_v2"
    params: dict = {
        "since": since,
        "before": before,
        "limit": PAGE_LIMIT,
    }
    if action_type:
        params["action.type"] = action_type

    all_logs: list[dict] = []
    cursor = None
    page = 0

    while True:
        page += 1
        if cursor:
            params["cursor"] = cursor

        resp = session.get(url, params=params, timeout=30)

        if resp.status_code == 403:
            sys.exit(
                "Error 403 Forbidden - check your API token "
                "(required permission: Account -> Audit Logs -> Read)"
            )
        if resp.status_code == 400:
            sys.exit(f"Error 400 Bad Request - {resp.text}")
        resp.raise_for_status()

        data = resp.json()

        if not data.get("success", False):
            sys.exit(f"API returned an error: {data.get('errors')}")

        result = data.get("result") or []
        all_logs.extend(result)

        print(
            f"  Page {page}: {len(result)} records "
            f"(total {len(all_logs)})",
            file=sys.stderr,
        )

        # Cursor pagination - if the API does not return a next cursor, stop
        result_info = data.get("result_info") or {}
        cursor = result_info.get("cursor")
        if not cursor or len(result) < PAGE_LIMIT:
            break

    return all_logs


def fmt_actor(actor: dict) -> str:
    """Human-readable description of the actor."""
    if not actor:
        return "?"
    email = actor.get("email") or actor.get("id") or "?"
    actor_type = actor.get("type", "user")
    ip = actor.get("ip") or ""
    return f"{email} ({actor_type})" + (f" [{ip}]" if ip else "")


def fmt_record(rec: dict) -> str:
    """One record per line."""
    when = rec.get("when") or rec.get("time") or "?"
    action = rec.get("action") or {}
    if isinstance(action, dict):
        action_name = action.get("type", "?")
        action_desc = action.get("description", "")
    else:
        action_name = str(action)
        action_desc = ""
    actor = fmt_actor(rec.get("actor") or {})
    resource = rec.get("resource") or {}
    if isinstance(resource, dict):
        res_desc = (
            resource.get("description")
            or resource.get("name")
            or resource.get("id")
            or "-"
        )
        res_type = resource.get("type", "")
    else:
        res_desc, res_type = str(resource), ""

    line = f"{when}  |  {action_name:<28} |  {actor}"
    if action_desc:
        line += f"  |  {action_desc}"
    if res_type or res_desc != "-":
        line += f"  |  {res_type}:{res_desc}"
    return line


def main() -> None:
    parser = argparse.ArgumentParser(description="Download Cloudflare audit logs (read-only demo)")
    parser.add_argument("--since", help="Start of range in ISO8601, e.g. 2026-09-17T00:00:00Z")
    parser.add_argument("--before", help="End of range in ISO8601 (default: now)")
    parser.add_argument("--action", help="Filter by action type, e.g. login")
    parser.add_argument("--json", action="store_true", help="Print full JSON of every record")
    parser.add_argument("--raw", action="store_true", help="Print raw API response (no formatting)")
    args = parser.parse_args()

    # Check that credentials were loaded
    if not API_TOKEN or not ACCOUNT_ID:
        sys.exit(
            "Could not load credentials.\n"
            "Options:\n"
            f"  1. Create a {ENV_FILE} file with:\n"
            "       CF_API_TOKEN=...\n"
            "       CF_ACCOUNT_ID=...\n"
            "  2. Or set the CF_API_TOKEN and CF_ACCOUNT_ID env vars\n"
            "API token must have permission: Account -> Audit Logs -> Read"
        )

    since = args.since or iso_hours_ago(DEFAULT_LOOKBACK_HOURS)
    before = args.before or iso_now()

    print(f"Account:      {ACCOUNT_ID}")
    print(f"Range:        {since} -> {before}")
    if args.action:
        print(f"Action filter: {args.action}")
    print("-" * 100)

    session = build_session()

    print("Downloading audit logs...", file=sys.stderr)
    logs = fetch_audit_logs(session, since, before, args.action)

    print("-" * 100)
    if not logs:
        print("No audit logs found in the given range.")
        return

    print(f"Found {len(logs)} records:\n")

    if args.raw:
        print(json.dumps(logs, indent=2, ensure_ascii=False))
        return

    for rec in logs:
        if args.json:
            print(json.dumps(rec, indent=2, ensure_ascii=False))
            print("-" * 60)
        else:
            print(fmt_record(rec))

    print("-" * 100)
    print(f"Total: {len(logs)} records")


if __name__ == "__main__":
    main()
