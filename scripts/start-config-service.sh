#!/bin/bash
# Start config service with mTLS enforcement

set -e

echo "🚀 Starting AceIoT Configuration Service with mTLS..."

# Create certs directory
mkdir -p /app/certs

# Generate server certificates if they don't exist
if [ ! -f /app/certs/server.crt ]; then
    echo "📜 Server certificates not found, generating..."
    bash /app/scripts/generate-server-certs.sh
else
    echo "✅ Using existing server certificates"
fi

# Verify certificates exist
if [ ! -f /app/certs/server.crt ] || [ ! -f /app/certs/server.key ] || [ ! -f /app/certs/ca-chain.crt ]; then
    echo "❌ Error: Required certificate files not found!"
    exit 1
fi

echo "🔒 Starting uvicorn with mTLS enforcement..."
echo "   - Server cert: /app/certs/server.crt"
echo "   - Server key:  /app/certs/server.key"
echo "   - CA chain:    /app/certs/ca-chain.crt"
echo "   - Client certs: REQUIRED (ssl-cert-reqs=2)"
echo ""

# Start uvicorn with TLS and client certificate requirement
exec uvicorn src.config_service.main:app \
    --host 0.0.0.0 \
    --port 8501 \
    --ssl-keyfile /app/certs/server.key \
    --ssl-certfile /app/certs/server.crt \
    --ssl-ca-certs /app/certs/ca-chain.crt \
    --ssl-cert-reqs 2 \
    --log-level info
