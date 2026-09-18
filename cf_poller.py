#!/usr/bin/env python3
"""
Cloudflare -> Syslog/JSONL poller (read-only), v2.

Design principles:

  1. INDIVIDUAL EVENTS (firewallEventsAdaptive, httpRequestsAdaptive,
     dnsAnalyticsAdaptive) - full second-level precision, no aggregation
     and no duplicate rows from count expansion.
  2. EVENT-DRIVEN CURSOR - the state file stores the timestamp of the
     last fetched event (+1s), not the wall-clock run time. No
     duplicates, no overlap windows, nothing is lost when the poller
     runs late.
  3. Only COMPLETED intervals are queried (until = now - 1 min for GraphQL).
  4. ATOMIC state save (temp file + rename).
  5. DAEMON mode (--daemon) with CF_POLL_INTERVAL, SIGTERM handling
     and a systemd unit file (cf-poller.service).
  6. Two output modes: CEF syslog (UDP) and JSONL on stdout
     ({"ts","source","zone","data"} - pipe into Vector/Loki/journald).
  7. zt_access source - logins/logouts to apps protected by Cloudflare Access.
  8. Per-source error handling - one failing dataset does not stop the others.
  9. CF_ZONE_IDS configuration + zone cache (fewer API calls).

Sources:
    audit       - audit logs (REST audit_logs_v2), cursor = event time
    zt_access   - Cloudflare Access login/logout (REST)
    security    - firewall/WAF events per zone (GraphQL, individual)
    requests    - HTTP requests per zone (GraphQL, individual, sampled)
    dns         - DNS queries per zone (GraphQL, individual)

Usage:
    python3 cf_poller.py                     # one incremental run
    python3 cf_poller.py --daemon            # loop with CF_POLL_INTERVAL
    python3 cf_poller.py --dry-run           # print CEF, do not send/save
    python3 cf_poller.py --stdout            # JSONL to stdout (for Vector/pipe)
    python3 cf_poller.py --datasets audit,security
    python3 cf_poller.py --since ... --before ...
    python3 cf_poller.py --reset             # clear the state

Configuration: .env (CF_API_TOKEN, CF_ACCOUNT_ID, SYSLOG_HOST/PORT,
FACILITY_*, DEFAULT_LOOKBACK_HOURS, QUERY_LIMIT, CF_POLL_INTERVAL,
CF_ZONE_IDS, OUTPUT, STATE_FILE)
"""

import argparse
import json
import os
import signal
import socket
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Error: missing the 'requests' library. Install it with: pip install requests")

SCRIPT_DIR = Path(__file__).resolve().parent
ENV_FILE = SCRIPT_DIR / ".env"

CF_API_BASE = "https://api.cloudflare.com/client/v4"
CF_GRAPHQL_URL = f"{CF_API_BASE}/graphql"

DEFAULT_SOURCES = ["audit", "zt_access", "security", "requests", "dns"]

TAGS = {
    "audit": "cloudflare-audit",
    "zt_access": "cloudflare-zt-access",
    "security": "cloudflare-security",
    "requests": "cloudflare-requests",
    "dns": "cloudflare-dns",
}
FACILITY_KEYS = {
    "audit": "FACILITY_AUDIT",
    "zt_access": "FACILITY_ZT_ACCESS",
    "security": "FACILITY_SECURITY",
    "requests": "FACILITY_REQUESTS",
    "dns": "FACILITY_DNS",
}
SOURCE_NAMES = {
    "audit": "Cloudflare audit event",
    "zt_access": "Cloudflare Access event",
    "security": "Cloudflare WAF/firewall event",
    "requests": "Cloudflare HTTP request",
    "dns": "Cloudflare DNS query",
}

# safety cap: max pages fetched per source per run (prevents endless loops)
MAX_PAGES = 20


# =====================================================================
# Configuration
# =====================================================================
def parse_env_file(path: "Path") -> dict:
    """Simple .env parser - KEY=VALUE lines, # comments, quotes stripped."""
    values = {}
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


def cfg(name: str, default: str = "") -> str:
    """Value from env vars (priority) or the .env file."""
    return os.environ.get(name) or _ENV.get(name, default)


def cfg_int(name: str, default: int) -> int:
    raw = cfg(name, "")
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


API_TOKEN = cfg("CF_API_TOKEN")
ACCOUNT_ID = cfg("CF_ACCOUNT_ID")
SYSLOG_HOST = cfg("SYSLOG_HOST")
SYSLOG_PORT = cfg_int("SYSLOG_PORT", 514)
SYSLOG_HOSTNAME = cfg("SYSLOG_HOSTNAME") or socket.gethostname()
DEFAULT_LOOKBACK_HOURS = cfg_int("DEFAULT_LOOKBACK_HOURS", 24)
QUERY_LIMIT = cfg_int("QUERY_LIMIT", 500)
POLL_INTERVAL = cfg_int("CF_POLL_INTERVAL", 300)
ZONE_IDS_CFG = [z.strip() for z in cfg("CF_ZONE_IDS").split(",") if z.strip()]
OUTPUT = cfg("OUTPUT", "cef").lower()  # cef | jsonl | both
STATE_FILE = SCRIPT_DIR / (cfg("STATE_FILE") or "cf_poller_state.json")


# =====================================================================
# Time helpers
# =====================================================================
def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> datetime:
    """Parse an ISO8601 timestamp (supports fractional seconds)."""
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def fmt_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =====================================================================
# State (atomic save, event-driven cursor)
# =====================================================================
def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            # migrate from the old format (audit_ids, wall-clock keys)
            if isinstance(data, dict) and "audit_ids" not in data:
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_state_atomic(state: dict) -> None:
    """Atomic write: temp file + rename (crash-safe)."""
    fd, tmp_path = tempfile.mkstemp(
        prefix=".cf_poller_state-", suffix=".tmp", dir=str(SCRIPT_DIR)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, STATE_FILE)
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# =====================================================================
# Syslog / CEF
# =====================================================================
def cef_escape(value) -> str:
    """Escape a value for a CEF extension field (backslash, |, =)."""
    s = "" if value is None else str(value)
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


def cef_sev_to_syslog(cef_sev: int) -> int:
    """Map CEF severity (0-10) to syslog severity (0-7)."""
    if cef_sev < 4:
        return 6   # informational
    if cef_sev < 7:
        return 4   # warning
    return 2       # critical


def build_cef_message(facility: int, tag: str, event_time: datetime,
                      signature_id: str, name: str, cef_sev: int,
                      ext: dict) -> str:
    """Build a complete syslog message (RFC3164 header + CEF payload)."""
    sev = cef_sev_to_syslog(cef_sev)
    pri = facility * 8 + sev
    ts = event_time.strftime("%b %e %H:%M:%S")
    header = (
        f"CEF:0|Cloudflare|CF-Poller|1.0|"
        f"{cef_escape(signature_id)}|{cef_escape(name)}|{cef_sev}|"
    )
    body = " ".join(f"{k}={cef_escape(v)}" for k, v in ext.items())
    payload = header + body
    # keep UDP datagrams reasonably small (~900B payload)
    if len(payload) > 900:
        payload = payload[:897] + "..."
    return f"<{pri}>{ts} {SYSLOG_HOSTNAME} {tag}: {payload}"


class SyslogSender:
    """UDP syslog sender; if SYSLOG_HOST is empty, messages are printed."""

    def __init__(self, dry_run: bool):
        self.dry = dry_run or not SYSLOG_HOST
        self.sock = None
        if not self.dry:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sent = 0

    def send(self, message: str) -> None:
        if self.dry:
            print(message)
        else:
            self.sock.sendto(message.encode("utf-8"), (SYSLOG_HOST, SYSLOG_PORT))
        self.sent += 1


class JsonlEmitter:
    """Emit events as JSONL envelopes to stdout (for Vector/pipes)."""

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.sent = 0

    def emit(self, ts: str, source: str, zone: str, data: dict) -> None:
        if not self.enabled:
            return
        env = {"ts": ts, "source": source, "zone": zone or None, "data": data}
        print(json.dumps(env, ensure_ascii=False))
        self.sent += 1


# =====================================================================
# HTTP
# =====================================================================
def build_session() -> "requests.Session":
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json",
            "User-Agent": "cf-poller/2.0",
        }
    )
    return s


def get_zones(session) -> list:
    """Zones from CF_ZONE_IDS config, or auto-discovery (cached per run)."""
    if ZONE_IDS_CFG:
        return [{"id": z, "name": z} for z in ZONE_IDS_CFG]
    resp = session.get(f"{CF_API_BASE}/zones", params={"per_page": 50}, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"zones API error: {data.get('errors')}")
    return data.get("result") or []


# =====================================================================
# Fetchers - all return a cursor = timestamp of the last fetched event
# =====================================================================
def fetch_audit(session, since: str) -> list:
    """Audit logs (REST audit_logs_v2, cursor pagination)."""
    url = f"{CF_API_BASE}/accounts/{ACCOUNT_ID}/audit_logs_v2"
    params = {"since": since, "limit": QUERY_LIMIT}
    logs = []
    cursor = None
    for _ in range(MAX_PAGES):
        if cursor:
            params["cursor"] = cursor
        resp = session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success"):
            raise RuntimeError(f"audit API error: {data.get('errors')}")
        result = data.get("result") or []
        logs.extend(result)
        result_info = data.get("result_info") or {}
        cursor = result_info.get("cursor")
        if not cursor or len(result) < QUERY_LIMIT:
            break
    return logs


def fetch_zt_access(session, since: str) -> list:
    """Cloudflare Access login/logout events (REST, page-based pagination)."""
    url = f"{CF_API_BASE}/accounts/{ACCOUNT_ID}/access/logs/access_requests"
    events = []
    page = 1
    for _ in range(MAX_PAGES):
        resp = session.get(
            url,
            params={
                "since": since,
                "per_page": QUERY_LIMIT,
                "page": page,
                "direction": "asc",
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success"):
            raise RuntimeError(f"zt_access API error: {data.get('errors')}")
        result = data.get("result") or []
        events.extend(result)
        result_info = data.get("result_info") or {}
        total = result_info.get("total_count", len(events))
        if page * QUERY_LIMIT >= total or not result:
            break
        page += 1
    return events


GRAPHQL_SOURCES = {
    "security": {
        "dataset": "firewallEventsAdaptive",
        "fields": """
        datetime action source kind
        clientIP clientCountryName clientAsn clientASNDescription
        clientRequestHTTPHost clientRequestHTTPMethodName clientRequestPath
        clientRequestQuery clientRequestHTTPProtocol userAgent
        edgeResponseStatus originResponseStatus wafAttackScoreClass
        ruleId rulesetId rayName edgeColoName""",
    },
    "requests": {
        "dataset": "httpRequestsAdaptive",
        "fields": """
        datetime clientRequestHTTPMethodName clientRequestHTTPHost
        clientRequestPath clientRequestQuery clientRequestHTTPProtocol
        edgeResponseStatus originResponseStatus cacheStatus wafAttackScoreClass
        clientIP clientCountryName clientASNDescription userAgent""",
    },
    "dns": {
        "dataset": "dnsAnalyticsAdaptive",
        "fields": """
        datetime queryName queryType responseCode responseCached
        protocol coloName""",
    },
}


def _gql_events_page(session, dataset_cfg: dict, zone_id: str, since: str, until: str) -> list:
    """Fetch one page of individual events for a zone."""
    query = f"""
query($zoneTag: string!, $since: Time!, $until: Time!, $limit: int!) {{
  viewer {{ zones(filter: {{ zoneTag: $zoneTag }}) {{
    {dataset_cfg['dataset']}(limit: $limit,
      filter: {{ datetime_geq: $since, datetime_lt: $until }},
      orderBy: [datetime_ASC]) {{
      {dataset_cfg['fields']}
    }}
  }} }}
}}
"""
    resp = session.post(
        CF_GRAPHQL_URL,
        json={
            "query": query,
            "variables": {
                "zoneTag": zone_id,
                "since": since,
                "until": until,
                "limit": QUERY_LIMIT,
            },
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("errors"):
        raise RuntimeError(f"GraphQL ({dataset_cfg['dataset']}) error: {data['errors']}")
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return []
    return zones[0].get(dataset_cfg["dataset"]) or []


def fetch_graphql_events(session, kind: str, zone: dict, since: str, until: str) -> list:
    """Fetch individual events with a moving cursor; paginate full pages."""
    dataset_cfg = GRAPHQL_SOURCES[kind]
    events = []
    cursor_since = since
    for _ in range(MAX_PAGES):
        page = _gql_events_page(session, dataset_cfg, zone["id"], cursor_since, until)
        events.extend(page)
        if len(page) < QUERY_LIMIT:
            break
        # full page -> continue from the last event's timestamp (+1s)
        last_dt = parse_iso(page[-1]["datetime"])
        cursor_since = fmt_iso(last_dt + timedelta(seconds=1))
        if cursor_since >= until:
            break
    return events


# =====================================================================
# CEF mappings - return (signature_id, event_time, severity, ext, raw)
# =====================================================================
def severity_for_security(rec: dict) -> int:
    action = (rec.get("action") or "").lower()
    if action == "block":
        return 7
    if action in ("challenge", "jschallenge", "managed_challenge", "interactive"):
        return 6
    if action in ("allow", "skip"):
        return 2
    if action == "log":
        return 3
    return 4


def cef_ext_base(event_time: datetime) -> dict:
    return {"rt": str(int(event_time.timestamp() * 1000))}


def map_audit(rec: dict):
    action = rec.get("action") or {}
    action_type = action.get("type", "unknown") if isinstance(action, dict) else str(action)
    event_time = parse_iso(rec.get("when") or iso_now())
    actor = rec.get("actor") or {}
    resource = rec.get("resource") or {}
    metadata = rec.get("metadata") or {}

    ext = cef_ext_base(event_time)
    ext["suser"] = actor.get("email") or actor.get("id") or ""
    ext["src"] = actor.get("ip") or ""
    ext["cs1"] = action_type
    ext["cs1Label"] = "cfAction"
    ext["cs2"] = (
        f"{resource.get('type', '')}:{resource.get('id', '')}"
        if isinstance(resource, dict) else str(resource)
    )
    ext["cs2Label"] = "cfResource"
    ext["cs3"] = " ".join(f"{k}={v}" for k, v in metadata.items() if v)
    ext["cs3Label"] = "cfMetadata"
    ext["cs4"] = actor.get("id", "")
    ext["cs4Label"] = "cfActorId"
    return action_type, event_time, 5, ext, rec


def map_zt_access(rec: dict):
    action = rec.get("action") or "unknown"
    event_time = parse_iso(rec.get("createdAt") or iso_now())

    ext = cef_ext_base(event_time)
    ext["suser"] = rec.get("email") or ""
    ext["src"] = rec.get("ipAddress") or ""
    ext["request"] = rec.get("appDomain") or ""
    ext["cs1"] = action
    ext["cs1Label"] = "cfAction"
    ext["cs2"] = rec.get("country") or ""
    ext["cs2Label"] = "cfCountry"
    ext["cs3"] = str(rec.get("allowed", ""))
    ext["cs3Label"] = "cfAllowed"
    ext["cs4"] = rec.get("rayID") or ""
    ext["cs4Label"] = "cfRayId"
    return action, event_time, 3, ext, rec


def map_security(rec: dict):
    action = rec.get("action") or "unknown"
    event_time = parse_iso(rec.get("datetime") or iso_now())
    uri = (
        f"{rec.get('clientRequestHTTPHost') or ''}"
        f"{rec.get('clientRequestPath') or ''}{rec.get('clientRequestQuery') or ''}"
    )
    ext = cef_ext_base(event_time)
    ext["src"] = rec.get("clientIP") or ""
    ext["request"] = uri
    ext["requestMethod"] = rec.get("clientRequestHTTPMethodName") or ""
    ext["app"] = rec.get("clientRequestHTTPProtocol") or ""
    ext["out"] = rec.get("edgeResponseStatus") or ""
    ext["in"] = rec.get("originResponseStatus") or ""
    ext["cs1"] = rec.get("source") or ""
    ext["cs1Label"] = "cfSource"
    ext["cs2"] = rec.get("ruleId") or ""
    ext["cs2Label"] = "cfRuleId"
    ext["cs3"] = rec.get("clientCountryName") or ""
    ext["cs3Label"] = "cfCountry"
    ext["cs4"] = rec.get("clientASNDescription") or ""
    ext["cs4Label"] = "cfASN"
    ext["cs5"] = rec.get("wafAttackScoreClass") or ""
    ext["cs5Label"] = "cfWafClass"
    ext["requestClientApplication"] = (rec.get("userAgent") or "")[:200]
    return action, event_time, severity_for_security(rec), ext, rec


def map_requests(rec: dict):
    edge = rec.get("edgeResponseStatus") or 0
    try:
        edge_int = int(edge)
    except (TypeError, ValueError):
        edge_int = 0
    sev = 8 if edge_int >= 500 else (5 if edge_int >= 400 else 3)
    event_time = parse_iso(rec.get("datetime") or iso_now())
    uri = (
        f"{rec.get('clientRequestHTTPHost') or ''}"
        f"{rec.get('clientRequestPath') or ''}{rec.get('clientRequestQuery') or ''}"
    )
    ext = cef_ext_base(event_time)
    ext["src"] = rec.get("clientIP") or ""
    ext["request"] = uri
    ext["requestMethod"] = rec.get("clientRequestHTTPMethodName") or ""
    ext["app"] = rec.get("clientRequestHTTPProtocol") or ""
    ext["out"] = edge
    ext["in"] = rec.get("originResponseStatus") or ""
    ext["cs1"] = rec.get("cacheStatus") or ""
    ext["cs1Label"] = "cfCacheStatus"
    ext["cs2"] = rec.get("wafAttackScoreClass") or ""
    ext["cs2Label"] = "cfWafClass"
    ext["cs3"] = rec.get("clientCountryName") or ""
    ext["cs3Label"] = "cfCountry"
    ext["cs4"] = rec.get("clientASNDescription") or ""
    ext["cs4Label"] = "cfASN"
    ext["requestClientApplication"] = (rec.get("userAgent") or "")[:200]
    return str(edge or "0"), event_time, sev, ext, rec


def map_dns(rec: dict):
    code = rec.get("responseCode") or "UNKNOWN"
    sev = 3 if code == "NOERROR" else 5
    event_time = parse_iso(rec.get("datetime") or iso_now())
    ext = cef_ext_base(event_time)
    ext["request"] = rec.get("queryName") or ""
    ext["cs1"] = rec.get("queryType") or ""
    ext["cs1Label"] = "cfQueryType"
    ext["cs2"] = code
    ext["cs2Label"] = "cfResponseCode"
    ext["cs3"] = rec.get("protocol") or ""
    ext["cs3Label"] = "cfProtocol"
    ext["cs4"] = rec.get("coloName") or ""
    ext["cs4Label"] = "cfColo"
    return code, event_time, sev, ext, rec


MAPPERS = {
    "audit": map_audit,
    "zt_access": map_zt_access,
    "security": map_security,
    "requests": map_requests,
    "dns": map_dns,
}


# =====================================================================
# Sources - returns a list of (key, kind, zone|None)
# =====================================================================
def build_sources(session, selected: list) -> list:
    zones = []
    needs_zones = any(k in selected for k in ("security", "requests", "dns"))
    if needs_zones:
        zones = get_zones(session)
    sources = []
    for kind in DEFAULT_SOURCES:
        if not any(k == kind or k.split(":")[0] == kind for k in selected):
            continue
        if kind in ("audit", "zt_access"):
            sources.append((kind, kind, None))
        else:
            for zone in zones:
                sources.append((f"{kind}:{zone['id']}", kind, zone))
    return sources


def process_source(session, sender: SyslogSender, jsonl: JsonlEmitter,
                   key: str, kind: str, zone: dict, since: str, until: str):
    """Fetch and emit events for one source. Returns (sent, cursor)."""
    if kind == "audit":
        events = fetch_audit(session, since)
    elif kind == "zt_access":
        events = fetch_zt_access(session, since)
    else:
        events = fetch_graphql_events(session, kind, zone, since, until)

    mapper = MAPPERS[kind]
    facility = cfg_int(FACILITY_KEYS[kind], 16)
    tag = TAGS[kind]
    name = SOURCE_NAMES[kind]
    sent = 0
    last_dt = None

    for rec in events:
        sig, event_time, sev, ext, raw = mapper(rec)
        if OUTPUT in ("cef", "both"):
            msg = build_cef_message(facility, tag, event_time, sig, name, sev, ext)
            sender.send(msg)
        if OUTPUT in ("jsonl", "both"):
            ts = (raw.get("datetime") or raw.get("when")
                  or raw.get("createdAt")
                  or event_time.strftime("%Y-%m-%dT%H:%M:%SZ"))
            zone_name = zone["name"] if zone else None
            jsonl.emit(ts, kind, zone_name, raw)
        sent += 1
        if last_dt is None or event_time > last_dt:
            last_dt = event_time

    # event-driven cursor: advance past the last fetched event
    if sent and last_dt is not None:
        return sent, fmt_iso(last_dt + timedelta(seconds=1))
    return sent, None


def run_cycle(session, sender: SyslogSender, jsonl: JsonlEmitter,
              selected: list, state: dict, since_override=None,
              until_override=None, verbose=False) -> dict:
    """One run over all sources. Returns {key: (events, sent)}."""
    sources = build_sources(session, selected)
    summary = {}
    for key, kind, zone in sources:
        st = state.get(key) or {}
        try:
            if since_override:
                since = since_override
            elif st.get("last"):
                since = st["last"]
            else:
                since = iso_hours_ago(DEFAULT_LOOKBACK_HOURS)

            # only completed intervals: until = now - 1 min (GraphQL);
            # REST sources (audit, zt_access) may query up to now
            until = until_override or (
                fmt_iso(datetime.now(timezone.utc) - timedelta(minutes=1))
                if kind not in ("audit", "zt_access") else iso_now()
            )

            if since >= until:
                summary[key] = (0, 0)
                continue

            sent, cursor = process_source(
                session, sender, jsonl, key, kind, zone, since, until
            )
            summary[key] = (sent, sent)
            if cursor:
                state[key] = {"last": cursor}
            if verbose:
                print(f"  [{key}] sent: {sent}", file=sys.stderr)
        except Exception as exc:  # per-source error handling (improvement #8)
            summary[key] = ("ERROR", str(exc)[:80])
            print(f"  [!] {key}: {exc}", file=sys.stderr)
    return summary


# =====================================================================
# Main
# =====================================================================
STOP = False


def handle_signal(signum, frame):
    global STOP
    STOP = True


def main() -> None:
    global OUTPUT

    parser = argparse.ArgumentParser(description="Cloudflare -> syslog (CEF) / JSONL poller v2")
    parser.add_argument("--datasets", help="Comma-separated sources: audit,zt_access,security,requests,dns")
    parser.add_argument("--since", help="Override the range start (ISO8601) - single run")
    parser.add_argument("--before", help="Override the range end (ISO8601)")
    parser.add_argument("--daemon", action="store_true", help="Infinite loop with CF_POLL_INTERVAL")
    parser.add_argument("--dry-run", action="store_true", help="Print CEF to stdout, do not send, do not save state")
    parser.add_argument("--stdout", action="store_true", help="JSONL envelope to stdout (instead of syslog)")
    parser.add_argument("--reset", action="store_true", help="Clear the saved state")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not API_TOKEN or not ACCOUNT_ID:
        sys.exit("Missing credentials - check .env (CF_API_TOKEN, CF_ACCOUNT_ID)")

    if args.stdout:
        OUTPUT = "jsonl"

    selected = [d.strip() for d in args.datasets.split(",")] if args.datasets else list(DEFAULT_SOURCES)
    for d in selected:
        if d.split(":")[0] not in DEFAULT_SOURCES:
            sys.exit(f"Unknown source '{d}'. Allowed: {', '.join(DEFAULT_SOURCES)}")

    state = load_state()
    if args.reset and STATE_FILE.exists():
        STATE_FILE.unlink()
        state = {}
        print("State cleared.", file=sys.stderr)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    session = build_session()
    sender = SyslogSender(args.dry_run)
    jsonl = JsonlEmitter(OUTPUT in ("jsonl", "both"))

    if sender.dry and not args.dry_run and OUTPUT not in ("jsonl", "both"):
        print("WARNING: SYSLOG_HOST is not set - printing to stdout only.", file=sys.stderr)

    def one_cycle():
        nonlocal state
        summary = run_cycle(
            session, sender, jsonl, selected, state,
            since_override=args.since, until_override=args.before,
            verbose=args.verbose,
        )
        if not args.dry_run:
            save_state_atomic(state)  # improvement #4
        print("-" * 70, file=sys.stderr)
        total = 0
        for key, val in summary.items():
            if isinstance(val, tuple) and val[0] != "ERROR":
                n = val[0]
                total += n
                print(f"{key:28s} sent: {n}", file=sys.stderr)
            else:
                print(f"{key:28s} ERROR: {val[1] if isinstance(val, tuple) else val}", file=sys.stderr)
        print(f"Total messages: {total}   [{iso_now()}]", file=sys.stderr)

    if args.daemon:
        # improvement #5: daemon with a ticker and clean shutdown
        print(f"Daemon mode, interval {POLL_INTERVAL}s. Ctrl+C/SIGTERM to stop.", file=sys.stderr)
        while not STOP:
            cycle_start = time.time()
            one_cycle()
            while not STOP and time.time() - cycle_start < POLL_INTERVAL:
                time.sleep(0.5)
        if not args.dry_run:
            save_state_atomic(state)
            print("State saved, exiting.", file=sys.stderr)
    else:
        one_cycle()


if __name__ == "__main__":
    main()
