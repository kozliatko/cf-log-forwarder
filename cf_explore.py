#!/usr/bin/env python3
"""
Interactive read-only explorer for Cloudflare log datasets.

Fetches one dataset and prints it to the console as a table, CSV or JSON.
Useful for manual inspection, ad-hoc CSV exports and debugging the poller.

Datasets:
    audit      - account audit logs (REST audit_logs_v2)
    security   - WAF/firewall events per zone (GraphQL, aggregated groups)
    requests   - HTTP requests per zone (GraphQL, aggregated groups)
    dns        - DNS query analytics per zone (GraphQL, aggregated groups)

Notes:
- Read-only; nothing is modified or persisted.
- On non-Enterprise plans, request/firewall data is SAMPLED and analytics
  retention is ~30 days.
- GraphQL sources use aggregated groups (each row = 'count' identical
  events within one minute). Individual events with second-level precision
  are fetched by cf_poller.py.

Usage:
    python3 cf_explore.py --dataset audit
    python3 cf_explore.py --dataset security --action block
    python3 cf_explore.py --dataset requests --host www.example.com --csv
    python3 cf_explore.py --dataset dns --code NXDOMAIN --json
    python3 cf_explore.py --dataset security --since 2026-09-17T00:00:00Z
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

API_BASE = "https://api.cloudflare.com/client/v4"
GRAPHQL_URL = f"{API_BASE}/graphql"

DATASETS = ("audit", "security", "requests", "dns")


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


DEFAULT_LOOKBACK_HOURS = cfg_int("DEFAULT_LOOKBACK_HOURS", 24)
QUERY_LIMIT = cfg_int("QUERY_LIMIT", 500)


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_session() -> requests.Session:
    """Session with auth headers - read-only access."""
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": "cf-explore/1.0",
        }
    )
    return s


def fetch_zone_list(session: requests.Session) -> list[dict]:
    """List zones available to the token (read-only)."""
    resp = session.get(f"{API_BASE}/zones", params={"per_page": 50}, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success", False):
        sys.exit(f"API error listing zones: {data.get('errors')}")
    return data.get("result") or []


# =====================================================================
# Dataset: audit (REST)
# =====================================================================
AUDIT_COLUMNS: list[tuple[str, str, int]] = [
    ("when",     "TIME",      20),
    ("_action",  "ACTION",    20),
    ("_actor",   "ACTOR",     34),
    ("_ip",      "IP",        16),
    ("_res",     "RESOURCE",  30),
    ("_meta",    "METADATA",  40),
]


def fetch_audit(session: requests.Session, since: str, before: str, args) -> list[dict]:
    """Fetch audit logs (cursor pagination) and flatten rows for the table."""
    url = f"{API_BASE}/accounts/{ACCOUNT_ID}/audit_logs_v2"
    params: dict = {"since": since, "before": before, "limit": QUERY_LIMIT}
    if args.action:
        params["action.type"] = args.action

    all_logs: list[dict] = []
    cursor = None
    while True:
        if cursor:
            params["cursor"] = cursor
        resp = session.get(url, params=params, timeout=30)
        if resp.status_code == 403:
            sys.exit("Error 403 Forbidden - check your API token "
                     "(required permission: Account -> Audit Logs -> Read)")
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success", False):
            sys.exit(f"API returned an error: {data.get('errors')}")
        result = data.get("result") or []
        all_logs.extend(result)
        result_info = data.get("result_info") or {}
        cursor = result_info.get("cursor")
        if not cursor or len(result) < QUERY_LIMIT:
            break

    rows: list[dict] = []
    for rec in all_logs:
        action = rec.get("action") or {}
        actor = rec.get("actor") or {}
        resource = rec.get("resource") or {}
        metadata = rec.get("metadata") or {}
        rows.append({
            "when": rec.get("when") or rec.get("time") or "?",
            "_action": action.get("type", "?") if isinstance(action, dict) else str(action),
            "_actor": actor.get("email") or actor.get("id") or "?",
            "_ip": actor.get("ip", "") if isinstance(actor, dict) else "",
            "_res": (f"{resource.get('type', '')}:{resource.get('id', '')}"
                     if isinstance(resource, dict) else str(resource)),
            "_meta": " ".join(f"{k}={v}" for k, v in (metadata or {}).items() if v),
        })
    return rows


# =====================================================================
# Datasets: security / requests / dns (GraphQL aggregated groups)
# =====================================================================
GRAPHQL_DATASETS = {
    "security": {
        "dataset": "firewallEventsAdaptiveGroups",
        "query": """
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
          datetimeMinute action source kind
          clientIP clientIPClass clientCountryName clientAsn clientASNDescription
          userAgent
          clientRequestHTTPHost clientRequestHTTPMethodName
          clientRequestPath clientRequestQuery clientRequestHTTPProtocol
          edgeResponseStatus originResponseStatus wafAttackScoreClass
          ruleId rulesetId rayName edgeColoName
        }
      }
    }
  }
}
""",
        "columns": [
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
            ("rayName",               "RAY_ID",       16),
            ("edgeColoName",          "COLO",         6),
        ],
        # NOTE: not available on the Business plan (Enterprise-only):
        #   botScore, botScoreSrcName, ja3Hash, ja4, wafAttackScore,
        #   wafSqliAttackScore, wafXssAttackScore, wafMlAttackScore
    },
    "requests": {
        "dataset": "httpRequestsAdaptiveGroups",
        "query": """
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
          clientRequestHTTPMethodName clientRequestHTTPHost
          clientRequestPath clientRequestQuery clientRequestHTTPProtocol
          edgeResponseStatus originResponseStatus cacheStatus wafAttackScoreClass
          clientIP clientCountryName clientASNDescription userAgent
        }
      }
    }
  }
}
""",
        "columns": [
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
        ],
    },
    "dns": {
        "dataset": "dnsAnalyticsAdaptiveGroups",
        "query": """
query DnsAnalytics($zoneTag: string!, $since: Time!, $before: Time!, $limit: int!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      dnsAnalyticsAdaptiveGroups(
        limit: $limit
        filter: { datetime_geq: $since, datetime_lt: $before }
        orderBy: [datetimeMinute_ASC]
      ) {
        count
        dimensions {
          datetimeMinute queryName queryType responseCode responseCached
          protocol coloName
        }
      }
    }
  }
}
""",
        "columns": [
            ("datetimeMinute", "TIME",      20),
            ("queryName",      "DOMAIN",    40),
            ("queryType",      "TYPE",      6),
            ("responseCode",   "CODE",      10),
            ("responseCached", "CACHE",     6),
            ("protocol",       "PROTOCOL",  8),
            ("coloName",       "COLO",      6),
        ],
    },
}


def fetch_graphql(session: requests.Session, kind: str, zone_tag: str,
                  since: str, before: str, args) -> list[dict]:
    """Fetch aggregated groups for one zone and expand 'count' to rows."""
    cfg = GRAPHQL_DATASETS[kind]
    filt: dict = {"datetime_geq": since, "datetime_lt": before}
    if kind == "security" and args.action:
        filt["action"] = args.action
    if kind == "requests" and args.host:
        filt["clientRequestHTTPHost"] = args.host
    if kind == "dns" and args.code:
        filt["responseCode"] = args.code

    resp = session.post(
        GRAPHQL_URL,
        json={
            "query": cfg["query"],
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
    groups = zones[0].get(cfg["dataset"]) or []

    events: list[dict] = []
    for group in groups:
        count = group.get("count", 1)
        dims = group.get("dimensions", {})
        for _ in range(count):
            events.append(dims)
    return events


# =====================================================================
# Output
# =====================================================================
def fmt_val(value) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def print_table(rows: list[dict], columns: list[tuple[str, str, int]]) -> None:
    print("  ".join(h.ljust(w)[:w] for _, h, w in columns))
    for rec in rows:
        print("  ".join(fmt_val(rec.get(k)).ljust(w)[:w] for k, _, w in columns))


def print_csv(rows: list[dict], columns: list[tuple[str, str, int]]) -> None:
    writer = csv.writer(sys.stdout)
    writer.writerow([h for _, h, _ in columns])
    for rec in rows:
        writer.writerow([fmt_val(rec.get(k)) for k, _, _ in columns])


# =====================================================================
# Main
# =====================================================================
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Explore Cloudflare log datasets (read-only)"
    )
    parser.add_argument("--dataset", required=True, choices=DATASETS,
                        help="Dataset to explore")
    parser.add_argument("--since", help="Start of range in ISO8601 (default: lookback window)")
    parser.add_argument("--before", help="End of range in ISO8601 (default: now)")
    parser.add_argument("--zone", help="Filter to a single zone (by name)")
    parser.add_argument("--action", help="[security] Filter by action: block, challenge, allow, log, skip...")
    parser.add_argument("--host", help="[requests] Filter by clientRequestHTTPHost")
    parser.add_argument("--code", help="[dns] Filter by responseCode (NOERROR, NXDOMAIN, SERVFAIL...)")
    parser.add_argument("--json", action="store_true", help="Print full JSON of every record")
    parser.add_argument("--csv", action="store_true", help="CSV output")
    parser.add_argument("--raw", action="store_true", help="[audit] Print raw API response")
    args = parser.parse_args()

    if not API_TOKEN or not ACCOUNT_ID:
        sys.exit(
            "Could not load credentials.\n"
            f"Create a {ENV_FILE} file with:\n"
            "  CF_API_TOKEN=...\n"
            "  CF_ACCOUNT_ID=...\n"
            "Or set the CF_API_TOKEN and CF_ACCOUNT_ID env vars."
        )

    since = args.since or iso_hours_ago(DEFAULT_LOOKBACK_HOURS)
    before = args.before or iso_now()

    session = build_session()

    print(f"Dataset:  {args.dataset}")
    print(f"Range:    {since} -> {before}")
    print("-" * 100, file=sys.stderr)

    if args.dataset == "audit":
        print(f"Account:  {ACCOUNT_ID}", file=sys.stderr)
        rows = fetch_audit(session, since, before, args)
        columns = AUDIT_COLUMNS
        if args.raw:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
            return
    else:
        zones = fetch_zone_list(session)
        if not zones:
            sys.exit("Token has no access to any zone "
                     "(required permission: Zone -> Analytics -> Read)")
        if args.zone:
            zones = [z for z in zones if z["name"] == args.zone]
            if not zones:
                sys.exit(f"Zone '{args.zone}' not found under this token.")
        print(f"Zones found: {', '.join(z['name'] for z in zones)}\n", file=sys.stderr)

        columns = GRAPHQL_DATASETS[args.dataset]["columns"]
        rows = []
        for zone in zones:
            print(f"=== Zone: {zone['name']} ===", file=sys.stderr)
            rows.extend(fetch_graphql(session, args.dataset, zone["id"], since, before, args))

    if not rows:
        print("No records found in the given range.")
        return

    print(f"Found {len(rows)} records\n", file=sys.stderr)

    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    elif args.csv:
        print_csv(rows, columns)
    else:
        print_table(rows, columns)


if __name__ == "__main__":
    main()
