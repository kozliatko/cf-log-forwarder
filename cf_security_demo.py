#!/usr/bin/env python3
"""
Demo script: downloads SECURITY (firewall/WAF) LOGS from Cloudflare
(read-only) and prints them to the console as a table - one field
per column.

- Uses the GraphQL Analytics API, dataset: firewallEventsAdaptiveGroups
- Read-only; nothing is modified or persisted.
- Note: on non-Enterprise plans firewall events are SAMPLED and
  retention is ~30 days. Full logs require Logpush (Enterprise).

Usage:
    python3 cf_security_demo.py
    python3 cf_security_demo.py --since 2026-09-16T00:00:00Z
    python3 cf_security_demo.py --action block
    python3 cf_security_demo.py --json      # raw JSON for every event
    python3 cf_security_demo.py --csv       # CSV output
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


def load_credentials() -> tuple[str, str]:
    """Read the API token and Account ID from env vars or the .env file."""
    token = os.environ.get("CF_API_TOKEN") or _ENV.get("CF_API_TOKEN", "")
    account = os.environ.get("CF_ACCOUNT_ID") or _ENV.get("CF_ACCOUNT_ID", "")
    return token, account


_ENV = parse_env_file(ENV_FILE)
API_TOKEN, ACCOUNT_ID = load_credentials()


def cfg_int(name: str, default: int) -> int:
    """Integer config from env vars (priority) or the .env file."""
    raw = os.environ.get(name) or _ENV.get(name, "")
    try:
        return int(raw) if raw else default
    except ValueError:
        return default
# =====================================================================

GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"

# Default time range: last 24 hours
DEFAULT_LOOKBACK_HOURS = cfg_int("DEFAULT_LOOKBACK_HOURS", 24)

# Max records per GraphQL query
QUERY_LIMIT = cfg_int("QUERY_LIMIT", 500)

GRAPHQL_QUERY = """
query FirewallEvents($zoneTag: string!, $since: Time!, $before: Time!, $limit: int!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      firewallEventsAdaptiveGroups(
        limit: $limit
        filter: { datetime_geq: $since, datetime_lt: $before }
        orderBy: [datetimeMinute_ASC]
      ) {
        count
        dimensions {
          # event time and classification
          datetimeMinute
          action
          source
          ruleId
          rulesetId
          kind
          # client
          clientIP
          clientIPClass
          clientCountryName
          clientAsn
          clientASNDescription
          userAgent
          # request
          clientRequestHTTPHost
          clientRequestHTTPMethodName
          clientRequestPath
          clientRequestQuery
          clientRequestHTTPProtocol
          # responses
          edgeResponseStatus
          originResponseStatus
          # WAF
          wafAttackScoreClass
          # identifiers
          rayName
          edgeColoName
        }
      }
    }
  }
}
"""

# Column order and labels for the table output
# (key = field in dimensions, header = column header, width = column width)
# NOTE: NOT available on the Business plan (Enterprise-only):
#   botScore, botScoreSrcName, ja3Hash, ja4, wafAttackScore,
#   wafSqliAttackScore, wafXssAttackScore, wafMlAttackScore
COLUMNS: list[tuple[str, str, int]] = [
    # (key, header, width)
    ("datetimeMinute",        "TIME",         20),
    ("action",                "ACTION",       18),
    ("source",                "SOURCE",       16),
    ("kind",                  "TYPE",         10),
    ("clientIP",              "IP",           16),
    ("clientIPClass",         "IP_CLASS",     10),
    ("clientCountryName",     "COUNTRY",      8),
    ("clientASNDescription",  "ASN",          22),
    ("clientRequestHTTPMethodName", "METHOD", 6),
    ("clientRequestHTTPHost", "HOST",         28),
    ("clientRequestPath",     "PATH",         34),
    ("clientRequestQuery",    "QUERY",        20),
    ("clientRequestHTTPProtocol", "PROTOCOL", 10),
    ("edgeResponseStatus",    "EDGE",         5),
    ("originResponseStatus",  "ORIGIN",       6),
    ("wafAttackScoreClass",   "WAF_CLASS",    10),
    ("ruleId",                "RULE_ID",      12),
    ("rulesetId",             "RULESET_ID",   12),
    ("rayName",               "RAY_ID",       16),
    ("edgeColoName",          "COLO",         6),
]


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def fetch_zone_list(session: requests.Session) -> list[dict]:
    """List zones available to the token (read-only)."""
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


def fetch_security_logs(
    session: requests.Session, zone_tag: str, since: str, before: str, action: str | None
) -> list[dict]:
    """Fetch firewall events for one zone via GraphQL."""
    filt = {"datetime_geq": since, "datetime_lt": before}
    if action:
        filt["action"] = action

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
    groups = zones[0].get("firewallEventsAdaptiveGroups") or []

    # Expand aggregated groups - each group contains 'count' identical events
    events: list[dict] = []
    for group in groups:
        count = group.get("count", 1)
        dims = group.get("dimensions", {})
        for _ in range(count):
            events.append(dims)
    return events


def fmt_val(value) -> str:
    """Convert a value to a string for the table."""
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def table_header() -> str:
    parts = []
    for _, header, width in COLUMNS:
        parts.append(header.ljust(width)[:width])
    return "  ".join(parts)


def table_row(rec: dict) -> str:
    parts = []
    for key, _, width in COLUMNS:
        val = fmt_val(rec.get(key))
        parts.append(val.ljust(width)[:width])
    return "  ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download Cloudflare security (firewall/WAF) logs (read-only demo)"
    )
    parser.add_argument("--since", help="Start of range in ISO8601, e.g. 2026-09-17T00:00:00Z")
    parser.add_argument("--before", help="End of range in ISO8601 (default: now)")
    parser.add_argument("--action", help="Filter by action: block, challenge, jschallenge, allow, log, skip...")
    parser.add_argument("--zone", help="Filter to a single zone (by name)")
    parser.add_argument("--json", action="store_true", help="Print full JSON of every event")
    parser.add_argument("--csv", action="store_true", help="CSV output")
    args = parser.parse_args()

    if not API_TOKEN or not ACCOUNT_ID:
        sys.exit(
            "Could not load credentials.\n"
            "Options:\n"
            f"  1. Create a {ENV_FILE} file with:\n"
            "       CF_API_TOKEN=...\n"
            "       CF_ACCOUNT_ID=...\n"
            "  2. Or set the CF_API_TOKEN and CF_ACCOUNT_ID env vars\n"
            "API token must have permission: Zone -> Analytics -> Read"
        )

    since = args.since or iso_hours_ago(DEFAULT_LOOKBACK_HOURS)
    before = args.before or iso_now()

    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": "cf-security-demo/1.0",
        }
    )

    print(f"Range:    {since} -> {before}", file=sys.stderr)
    if args.action:
        print(f"Action:   {args.action}", file=sys.stderr)
    print("-" * 110, file=sys.stderr)

    # 1. List zones under the token
    print("Listing available zones...", file=sys.stderr)
    zones = fetch_zone_list(session)
    if not zones:
        sys.exit("Token has no access to any zone (required permission: Zone -> Analytics -> Read)")

    if args.zone:
        zones = [z for z in zones if z["name"] == args.zone]
        if not zones:
            sys.exit(f"Zone '{args.zone}' not found under this token.")

    print(f"Zones found: {', '.join(z['name'] for z in zones)}\n", file=sys.stderr)

    csv_writer = None
    if args.csv:
        csv_writer = csv.writer(sys.stdout)
        csv_writer.writerow([header for _, header, _ in COLUMNS])

    # 2. Fetch security events for each zone
    total = 0
    for zone in zones:
        print(f"=== Zone: {zone['name']} ===", file=sys.stderr)
        events = fetch_security_logs(session, zone["id"], since, before, args.action)

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
