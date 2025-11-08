# Multi-stage Dockerfile for PKI Service
# Simplified for Podman Compose development
# Version: 2.0.0

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
    uv pip install --no-cache-dir fastapi uvicorn cryptography 'pydantic[email]' python-multipart email-validator jinja2

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM python:3.13-slim

LABEL maintainer="security@example.com" \
      description="PKI Service for Certificate Management" \
      version="2.0.0"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 pki && \
    useradd -u 1000 -g pki -s /bin/bash -m pki && \
    mkdir -p /app/data /app/logs && \
    chown -R pki:pki /app

# Copy virtual environment from builder
COPY --from=builder --chown=pki:pki /opt/venv /opt/venv

# Copy application source
COPY --chown=pki:pki src/ /app/src/

WORKDIR /app

# Switch to non-root user
USER pki

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PKI_DATA_DIR=/app/data \
    PKI_LOG_DIR=/app/logs

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()" || exit 1

# Run application with uvicorn
CMD ["python", "-m", "uvicorn", "src.pki_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
