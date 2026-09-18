# ============================================================
# Cloudflare syslog poller container
# Build:  docker build -t cf-poller .
# Run:    docker compose up -d
# ============================================================
FROM python:3.12-slim

LABEL description="Cloudflare -> syslog CEF log poller" \
      version="2.0.1"

# Dependencies (pinned to a CVE-free release, see GHSA for 2.31.x)
RUN pip install --no-cache-dir "requests>=2.32.4"

# Unprivileged user
RUN useradd --system --create-home --shell /usr/sbin/nologin cfpoller

WORKDIR /app
COPY cf_poller.py /app/

# Persistent directory for state (mounted as a volume)
RUN mkdir -p /data && chown -R cfpoller:cfpoller /app /data
USER cfpoller

# Default configuration values (everything can be overridden via env/env_file)
ENV STATE_FILE=/data/cf_poller_state.json \
    OUTPUT=cef

# Liveness: the poller writes its cursor state after every daemon cycle,
# so a stale state file means the loop is hung. The freshness threshold is
# 2x the poll interval (min 10 min) to tolerate slow cycles and start-up.
HEALTHCHECK --interval=5m --timeout=10s --start-period=10m --retries=2 \
  CMD python3 -c "import os,sys,time;p=os.environ.get('STATE_FILE','/data/cf_poller_state.json');n=int(os.environ.get('CF_POLL_INTERVAL','300'));sys.exit(0 if os.path.exists(p) and (time.time()-os.path.getmtime(p)) < max(600, 2*n) else 1)"

# The ENTRYPOINT also allows one-shot commands:
#   docker run cf-poller --dry-run
#   docker run cf-poller --stdout --datasets audit
ENTRYPOINT ["python3", "cf_poller.py"]
CMD ["--daemon"]
