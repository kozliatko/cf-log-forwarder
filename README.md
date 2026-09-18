# cf-log-forwarder

[![Security](https://github.com/kozliatko/cf-log-forwarder/actions/workflows/security.yml/badge.svg)](https://github.com/kozliatko/cf-log-forwarder/actions/workflows/security.yml)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

A read-only Python poller that fetches logs from the Cloudflare API and
forwards them to a syslog server in **CEF format** (UDP) or emits them as
**JSON lines** for any log pipeline.

Works on **non-Enterprise plans** (tested on Business) - no Logpush
required. Designed to run as a systemd service or a Docker container.

## What it exports

| Source      | Description                              | API            |
|-------------|------------------------------------------|----------------|
| `audit`     | Account audit log (config changes, logins, token management) | REST `audit_logs_v2` |
| `zt_access` | Cloudflare Access login/logout events    | REST           |
| `security`  | WAF / firewall events per zone           | GraphQL `firewallEventsAdaptive` |
| `requests`  | HTTP requests per zone (sampled on non-Enterprise plans) | GraphQL `httpRequestsAdaptive` |
| `dns`       | DNS queries resolved for the zone        | GraphQL `dnsAnalyticsAdaptive` |

## Design

- **Individual events** (not aggregated groups) - full second-level
  timestamps, no duplicate rows.
- **Event-driven cursor** - the state file stores the timestamp of the
  last fetched event (`+1s`), not the wall-clock run time. No duplicates,
  no overlap windows, nothing is lost if the poller runs late.
- **Only completed intervals** are queried (GraphQL `until = now - 1 min`).
- **Atomic state save** (temp file + rename) - crash-safe.
- **Per-source error handling** - one failing dataset does not stop the others.

## Output formats

### CEF over syslog (default)

Each event becomes one RFC3164 syslog message with a CEF payload:

```
<146>Sep 18 02:27:40 myhost cloudflare-security: CEF:0|Cloudflare|CF-Poller|1.0|block|Cloudflare WAF/firewall event|7|rt=1789698460000 src=203.0.113.8 request=www.example.com/sitemap.xml requestMethod=GET app=HTTP/2 out=403 cs1=firewallManaged cs1Label=cfSource ...
```

- Standard CEF fields: `src`, `request`, `requestMethod`, `app`, `out`,
  `in`, `rt`, `suser`
- Custom fields with labels: `cfAction`, `cfSource`, `cfRuleId`,
  `cfCountry`, `cfASN`, `cfWafClass`, `cfZone`, ...
- Each source type uses a **separate syslog facility** (`local1`-`local5`
  by default, configurable) so a rsyslog server can route them easily:

```
# /etc/rsyslog.d/30-cloudflare.conf
local1.*  /var/log/cloudflare/audit.log
local2.*  /var/log/cloudflare/security.log
local3.*  /var/log/cloudflare/requests.log
local4.*  /var/log/cloudflare/dns.log
local5.*  /var/log/cloudflare/zt-access.log
```

### JSONL (alternative)

Use `--stdout` (or `OUTPUT=jsonl`) to emit a JSON envelope per event on
stdout - ideal for piping into Vector, Loki, journald or any aggregator:

```json
{"ts": "2026-09-18T05:00:25Z", "source": "dns", "zone": "example.com", "data": {...}}
```

## Requirements

- Python 3.10+ (or the provided Docker image)
- `requests` library
- Cloudflare API token with:
  - `Account -> Audit Logs -> Read`
  - `Account -> Zero Trust -> Read` (only for `zt_access`)
  - `Zone -> Analytics -> Read` (for `security`, `requests`, `dns`)

## Configuration

All configuration is read from a `.env` file next to the script or from
environment variables (env vars take priority). See `.env.example`.

| Variable | Default | Description |
|----------|---------|-------------|
| `CF_API_TOKEN` | - | Scoped API token (required) |
| `CF_ACCOUNT_ID` | - | Cloudflare Account ID (required) |
| `SYSLOG_HOST` | *(empty)* | Syslog server address. If empty, messages are printed to stdout instead of sent |
| `SYSLOG_PORT` | `514` | Syslog UDP port |
| `SYSLOG_HOSTNAME` | *(hostname)* | Hostname in the syslog header |
| `OUTPUT` | `cef` | `cef`, `jsonl` or `both` |
| `DEFAULT_LOOKBACK_HOURS` | `24` | Lookback window on the first run (no state) |
| `QUERY_LIMIT` | `500` | Records per API query / page |
| `CF_POLL_INTERVAL` | `300` | Daemon mode interval in seconds |
| `CF_ZONE_IDS` | *(auto)* | Comma-separated zone IDs; empty = auto-discovery |
| `STATE_FILE` | `cf_poller_state.json` | Cursor state file (relative to the script) |
| `FACILITY_AUDIT` | `17` | Syslog facility (16-23 = local0-local7) |
| `FACILITY_ZT_ACCESS` | `21` | Syslog facility for Access events |
| `FACILITY_SECURITY` | `18` | Syslog facility for WAF events |
| `FACILITY_REQUESTS` | `19` | Syslog facility for HTTP requests |
| `FACILITY_DNS` | `20` | Syslog facility for DNS analytics |

## Usage

```bash
cp .env.example .env    # then fill in your values

# one incremental run
python3 cf_poller.py

# dry run (print CEF messages, do not send, do not save state)
python3 cf_poller.py --dry-run

# JSONL output (pipe anywhere)
python3 cf_poller.py --stdout | vector --config vector.toml

# selected sources only
python3 cf_poller.py --datasets audit,security

# explicit time window (ignores the saved cursor for this run)
python3 cf_poller.py --since 2026-09-18T00:00:00Z --before 2026-09-18T06:00:00Z

# clear the state and start over from the lookback window
python3 cf_poller.py --reset

# daemon mode (uses CF_POLL_INTERVAL)
python3 cf_poller.py --daemon
```

## Deployment

### systemd (recommended)

```bash
sudo mkdir -p /opt/cf-poller
sudo cp cf_poller.py /opt/cf-poller/
sudo cp .env /opt/cf-poller/
sudo chmod 600 /opt/cf-poller/.env
sudo cp cf-poller.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cf-poller
journalctl -fu cf-poller
```

### Docker

```bash
docker compose up -d --build
docker compose logs -f cf-poller

# one-shot commands
docker compose run --rm cf-poller --dry-run
```

The `.env` file is **not baked into the image** - it is injected via
`env_file` at runtime. The cursor state persists in `./data/` on the host.

The image includes a `HEALTHCHECK` based on state-file freshness: the
poller writes its cursor state after every daemon cycle, so a stale state
file (older than 2x `CF_POLL_INTERVAL`, min 10 minutes) marks the
container as unhealthy - a hung loop is detected without any extra
tooling inside the container.

> **Note:** inside a container `localhost` is the container itself -
> `SYSLOG_HOST` must point to the syslog server's IP address.

### cron (alternative to systemd)

```
*/5 * * * * cd /opt/cf-poller && /usr/bin/python3 cf_poller.py >> /var/log/cf_poller.log 2>&1
```

## Exploring datasets

`cf_explore.py` is a standalone read-only tool for inspecting each dataset
interactively (table / CSV / JSON output to the console):

```bash
python3 cf_explore.py --dataset audit                      # audit logs
python3 cf_explore.py --dataset security --action block    # WAF events
python3 cf_explore.py --dataset requests --host example.com --csv
python3 cf_explore.py --dataset dns --code NXDOMAIN --json
```

## State / backfill

The cursor state is a JSON file mapping each source key to the timestamp
of its last fetched event. To backfill, seed it manually:

```bash
echo '{"audit": {"last": "2026-01-01T00:00:00Z"}}' > cf_poller_state.json
```

## Plan limitations

Tested on the **Business** plan:

- HTTP requests and firewall events are **sampled** on non-Enterprise
  plans (`sampleInterval`); counts are representative, not exhaustive.
- Firewall/HTTP analytics retention is ~30 days - keep the poller running.
- Enterprise-only fields are not available: `botScore`, `ja3Hash`, `ja4`,
  numeric WAF attack scores (`wafAttackScore`, `wafSqliAttackScore`, ...).
- Logpush (native push of full logs) is Enterprise-only - this poller is
  the API-based alternative.

## Security notes

- The API token should be **read-only** (Analytics + Audit Logs read).
- Keep `.env` out of version control (`.gitignore` handles this).
- All requests are GET/POST to the Cloudflare API; nothing is written to
  your Cloudflare account.

## License

MIT - see [LICENSE](LICENSE).
