# Multi-stage hardened production Dockerfile for AI Autonomous Bug Hunter
FROM python:3.13-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final runtime image
FROM python:3.13-slim AS runtime

# Install minimal network tools required for tactical adapters (curl, dig)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    dnsutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create unprivileged system user and group (uid/gid 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /usr/sbin/nologin -M appuser

WORKDIR /app

# Copy installed python dependencies from builder
COPY --from=builder /root/.local /home/appuser/.local
ENV PATH="/home/appuser/.local/bin:/usr/local/bin:/usr/bin:/bin"
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Copy application source
COPY --chown=appuser:appgroup runtime/ /app/runtime/
COPY --chown=appuser:appgroup hunter/ /app/hunter/
COPY --chown=appuser:appgroup scripts/ /app/scripts/
COPY --chown=appuser:appgroup AGENTS.md requirements.txt pytest.ini /app/

# Create dedicated persistent directories for state and evidence
RUN mkdir -p /app/state /app/workspace && \
    chown -R appuser:appgroup /app/state /app/workspace && \
    chmod 750 /app/state /app/workspace

# Switch to unprivileged non-root user
USER appuser:appgroup

# Health check verifies runtime integrity without external network calls
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "from runtime.bootstrap import HunterRuntime; rt = HunterRuntime(); h = rt.health(); exit(0 if h.get('status') in ('READY', 'DEGRADED') else 1)"

# Read-only root filesystem compatible entrypoint
ENTRYPOINT ["python", "-m", "runtime.adapter.mcp_server", "--project-root", "/app"]
