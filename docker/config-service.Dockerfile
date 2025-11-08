# Multi-stage Dockerfile for Configuration Service
# FastAPI-based configuration interface with mTLS
# Version: 3.0.0

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM python:3.13-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy dependency files
COPY pyproject.toml uv.lock* ./

# Install uv and dependencies
RUN pip install --no-cache-dir uv && \
    uv venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv pip install --no-cache-dir fastapi uvicorn cryptography pyyaml python-dotenv pydantic jinja2

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM python:3.13-slim

LABEL maintainer="security@example.com" \
      description="Configuration Service with mTLS Authentication" \
      version="3.0.0"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    openssl \
    jq \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 config && \
    useradd -u 1000 -g config -s /bin/bash -m config && \
    mkdir -p /app/config /app/logs /app/certs /app/scripts && \
    chown -R config:config /app

# Copy virtual environment
COPY --from=builder --chown=config:config /opt/venv /opt/venv

# Copy application source
COPY --chown=config:config src/ /app/src/

# Copy startup scripts
COPY --chown=config:config scripts/generate-server-certs.sh /app/scripts/
COPY --chown=config:config scripts/start-config-service.sh /app/scripts/

# Make scripts executable
RUN chmod +x /app/scripts/*.sh

WORKDIR /app

# Switch to non-root user
USER config

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    CONFIG_DIR=/app/config \
    LOG_DIR=/app/logs \
    PKI_URL=http://pki-service:8000 \
    API_KEY=dev-key-12345

EXPOSE 8501

# Health check (HTTP - before TLS is configured)
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8501/health || exit 1

# Run configuration service with mTLS
CMD ["/app/scripts/start-config-service.sh"]
