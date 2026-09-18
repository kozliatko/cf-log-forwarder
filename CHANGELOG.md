# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-09-18

### Added
- Individual (non-aggregated) event fetching: `firewallEventsAdaptive`,
  `httpRequestsAdaptive`, `dnsAnalyticsAdaptive` - full second-level
  timestamp precision.
- Event-driven cursor: the state stores the timestamp of the last fetched
  event per source, eliminating duplicates and overlap windows.
- `zt_access` source - Cloudflare Access login/logout events.
- Daemon mode (`--daemon`) with configurable `CF_POLL_INTERVAL`,
  SIGTERM/SIGINT handling and a systemd unit file (`cf-poller.service`).
- JSONL output mode (`--stdout`, `OUTPUT=jsonl|both`) with a
  `{"ts","source","zone","data"}` envelope.
- Docker support: Dockerfile, docker-compose.yml, `.dockerignore`.
- `CF_ZONE_IDS` configuration option with zone auto-discovery fallback.
- Per-source error handling - a failing dataset does not stop the others.
- Comprehensive configuration via `.env` (syslog host/port, facilities,
  lookback window, query limits, output mode).

### Changed
- Syslog output uses CEF format with standard fields (`src`, `request`,
  `rt`, ...) and labelled custom fields (`cfAction`, `cfZone`, ...).
- Each source type is sent with a separate configurable syslog facility.
- State file is written atomically (temp file + rename).

### Removed
- Wall-clock polling windows with overlap and ID-based deduplication
  (replaced by the event-driven cursor).

## [1.0.0] - 2026-09-18

### Added
- Initial release.
- Demo/read-only scripts exploring each Cloudflare dataset:
  `cf_audit_demo.py`, `cf_security_demo.py`, `cf_requests_demo.py`,
  `cf_dns_demo.py`.
- `cf_poller.py` v1: incremental poller forwarding audit logs, WAF events,
  HTTP requests and DNS analytics to a syslog server in CEF format over
  UDP with per-dataset syslog facilities.
