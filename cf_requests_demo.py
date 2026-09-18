#!/usr/bin/env python3
"""
Demo script: downloads HTTP REQUEST LOGS from Cloudflare (read-only) and
prints them to the console as a table - one field per column.

- Uses the GraphQL Analytics API, dataset: httpRequestsAdaptiveGroups
- Read-only; nothing is modified or persisted.
- Note: on non-Enterprise plans requests are SAMPLED.

Usage:
    python3 cf_requests_demo.py
    python3 cf_requests_demo.py --since 2026-09-17T00:00:00Z
    python3 cf_requests_demo.py --host www.example.com   # filter by host
    python3 cf_requests_demo.py --json
    python3 cf_requests_demo.py --csv
"""

import argparse
import csv
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
# Configuration - credentials from .env or env vars
# =====================================================================
SCRIPT_DIR = Path(__file__).resolve().parent
ENV_FILE = SCRIPT_DIR / ".env"


def parse_env_file(path: Path) -> dict[str, str]:
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


def load_credentials() -> tuple[str, str]:
    env = parse_env_file(ENV_FILE)
    token = os.environ.get("CF_API_TOKEN") or env.get("CF_API_TOKEN", "")
    account = os.environ.get("CF_ACCOUNT_ID") or env.get("CF_ACCOUNT_ID", "")
    return token, account


_ENV = parse_env_file(ENV_FILE)
API_TOKEN, ACCOUNT_ID = load_credentials()


def cfg_int(name: str, default: int) -> int:
    raw = os.environ.get(name) or _ENV.get(name, "")
    try:
        return int(raw) if raw else default
    except ValueError:
        return default
# =====================================================================

GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"
DEFAULT_LOOKBACK_HOURS = cfg_int("DEFAULT_LOOKBACK_HOURS", 24)
QUERY_LIMIT = cfg_int("QUERY_LIMIT", 500)

GRAPHQL_QUERY = """
query HttpRequests($zoneTag: string!, $since: Time!, $before: Time!, $limit: int!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      httpRequestsAdaptiveGroups(
        limit: $limit
        filter: { datetime_geq: $since, datetime_lt: $before }
        orderBy: [datetimeMinute_ASC]
      ) {
        count
        dimensions {
          datetimeMinute
          clientRequestHTTPMethodName
          clientRequestHTTPHost
          clientRequestPath
          clientRequestQuery
          clientRequestHTTPProtocol
          edgeResponseStatus
          originResponseStatus
          cacheStatus
          wafAttackScoreClass
          clientIP
          clientCountryName
          clientASNDescription
          userAgent
        }
      }
    }
  }
}
"""

COLUMNS: list[tuple[str, str, int]] = [
    ("datetimeMinute",              "TIME",        20),
    ("clientRequestHTTPMethodName", "METHOD",      6),
    ("clientRequestHTTPHost",       "HOST",        28),
    ("clientRequestPath",           "PATH",        34),
    ("clientRequestQuery",          "QUERY",       20),
    ("clientRequestHTTPProtocol",   "PROTOCOL",    8),
    ("edgeResponseStatus",          "EDGE",        5),
    ("originResponseStatus",        "ORIGIN",      6),
    ("cacheStatus",                 "CACHE",       10),
    ("wafAttackScoreClass",         "WAF_CLASS",   10),
    ("clientIP",                    "IP",          16),
    ("clientCountryName",           "COUNTRY",     8),
    ("clientASNDescription",        "ASN",         22),
    ("userAgent",                   "USER_AGENT",  40),
]


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_zone_list(session: requests.Session) -> list[dict]:
    resp = session.get(
        "https://api.cloudflare.com/client/v4/zones",
        params={"per_page": 50},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success", False):
        sys.exit(f"API error listing zones: {data.get('errors')}")
    return data.get("result") or []


def fetch_requests(
    session: requests.Session, zone_tag: str, since: str, before: str, host: str | None
) -> list[dict]:
    filt: dict = {"datetime_geq": since, "datetime_lt": before}
    if host:
        filt["clientRequestHTTPHost"] = host

    resp = session.post(
        GRAPHQL_URL,
        json={
            "query": GRAPHQL_QUERY,
            "variables": {
                "zoneTag": zone_tag,
                "since": since,
                "before": before,
                "limit": QUERY_LIMIT,
            },
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("errors"):
        sys.exit(f"GraphQL error: {json.dumps(data['errors'], indent=2, ensure_ascii=False)}")

    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return []
    groups = zones[0].get("httpRequestsAdaptiveGroups") or []

    events: list[dict] = []
    for group in groups:
        count = group.get("count", 1)
        dims = group.get("dimensions", {})
        for _ in range(count):
            events.append(dims)
    return events


def fmt_val(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)


def table_header() -> str:
    return "  ".join(header.ljust(width)[:width] for _, header, width in COLUMNS)


def table_row(rec: dict) -> str:
    return "  ".join(fmt_val(rec.get(key)).ljust(width)[:width] for key, _, width in COLUMNS)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download Cloudflare HTTP request logs (read-only demo)"
    )
    parser.add_argument("--since", help="Start of range in ISO8601, e.g. 2026-09-17T00:00:00Z")
    parser.add_argument("--before", help="End of range in ISO8601 (default: now)")
    parser.add_argument("--host", help="Filter by clientRequestHTTPHost")
    parser.add_argument("--zone", help="Filter to a single zone (by name)")
    parser.add_argument("--json", action="store_true", help="Print full JSON of every event")
    parser.add_argument("--csv", action="store_true", help="CSV output")
    args = parser.parse_args()

    if not API_TOKEN or not ACCOUNT_ID:
        sys.exit(
            "Could not load credentials.\n"
            f"Create a {ENV_FILE} file with:\n"
            "  CF_API_TOKEN=...\n"
            "  CF_ACCOUNT_ID=...\n"
            "API token must have permission: Zone -> Analytics -> Read"
        )

    since = args.since or iso_hours_ago(DEFAULT_LOOKBACK_HOURS)
    before = args.before or iso_now()

    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": "cf-requests-demo/1.0",
        }
    )

    print(f"Range:    {since} -> {before}", file=sys.stderr)
    if args.host:
        print(f"Host:     {args.host}", file=sys.stderr)
    print("-" * 110, file=sys.stderr)

    zones = fetch_zone_list(session)
    if not zones:
        sys.exit("Token has no access to any zone.")
    if args.zone:
        zones = [z for z in zones if z["name"] == args.zone]
        if not zones:
            sys.exit(f"Zone '{args.zone}' not found under this token.")
    print(f"Zones found: {', '.join(z['name'] for z in zones)}\n", file=sys.stderr)

    csv_writer = None
    if args.csv:
        csv_writer = csv.writer(sys.stdout)
        csv_writer.writerow([header for _, header, _ in COLUMNS])

    total = 0
    for zone in zones:
        print(f"=== Zone: {zone['name']} ===", file=sys.stderr)
        events = fetch_requests(session, zone["id"], since, before, args.host)

        if not events:
            print("  (no events in the given range)", file=sys.stderr)
            continue

        if not args.csv and not args.json:
            print(table_header())

        for rec in events:
            if args.json:
                print(json.dumps(rec, indent=2, ensure_ascii=False))
            elif args.csv:
                csv_writer.writerow([fmt_val(rec.get(key)) for key, _, _ in COLUMNS])
            else:
                print(table_row(rec))

        total += len(events)
        print(f"  -> {len(events)} events", file=sys.stderr)

    if not args.json and not args.csv:
        print("-" * 110, file=sys.stderr)
    print(f"Total: {total} events", file=sys.stderr)


if __name__ == "__main__":
    main()
