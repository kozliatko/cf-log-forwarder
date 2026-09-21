# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.2] - 2026-09-21

### Fixed
- Docker deployment: the atomic state save created its temp file in the
  script directory while the target state file lives on a bind-mounted
  volume - `os.replace()` across filesystems fails with EXDEV, crashing
  the daemon into a restart loop with repeated 24h data refetch. The
  temp file is now created in the state file's directory (and missing
  parent directories are created).
- Docker deployment: bind-mounted `./data` is not writable by the
  container's unprivileged user (UID mismatch) - replaced with a named
  volume that inherits ownership from the image.
- A zero or negative `CF_POLL_INTERVAL` would turn the daemon into a
  hot loop continuously calling the Cloudflare API (rate-limit ban,
  log flooding) - the interval is now floored at 30 seconds.

### Added
- Fail-fast configuration validation: syslog facility (0-23) and port
  (1-65535) ranges are checked at startup with explicit error messages.
- Docker Compose runtime hardening: `no-new-privileges`, `cap_drop: ALL`,
  read-only root filesystem with a tmpfs `/tmp`.

### Changed
- New tests covering all the above (56 total).

## [2.0.1] - 2026-09-18

### Added
- Docker `HEALTHCHECK` based on state-file freshness (detects a hung
  daemon loop without extra tooling in the container).
- Unit test suite (50 tests): CEF escaping, payload truncation, message
  building, severity mappings, mappers, atomic state handling, emitters.
- CI pipeline (GitHub Actions): unit tests on push/PR to `main`;
  on green tests the Docker image is built and published to GHCR
  (tags: `latest`, `sha-<commit>`, and `x.y.z` for `v*` release tags).
- `cf_explore.py` - unified read-only dataset explorer
  (`--dataset audit|security|requests|dns`) replacing four separate
  demo scripts.

### Changed
- Dockerfile pins `requests>=2.32.4` (CVE-2024-35195, CVE-2024-47081).

### Fixed
- CEF payload truncation no longer splits `key=value` pairs or leaves
  dangling escape sequences - oversized messages are cut on a field
  boundary and remain syntactically valid CEF.
- `cef_escape` strips control characters (newline, tab, DEL, other
  bytes < 0x20) before escaping, preventing syslog framing violations
  and log injection via API-provided fields.
- `.env` parser: an inline `#` only starts a comment when preceded by
  whitespace, so values containing `#` are no longer silently
  truncated; quoted values are kept intact.

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
