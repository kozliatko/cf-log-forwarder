# ============================================================
# Cloudflare syslog poller container
# Build:  docker build -t cf-poller .
# Run:    docker compose up -d
# ============================================================
FROM python:3.12-slim

LABEL description="Cloudflare -> syslog CEF log poller" \
      version="2.0.0"

# Dependencies (requests only)
RUN pip install --no-cache-dir requests

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

# The ENTRYPOINT also allows one-shot commands:
#   docker run cf-poller --dry-run
#   docker run cf-poller --stdout --datasets audit
ENTRYPOINT ["python3", "cf_poller.py"]
CMD ["--daemon"]
