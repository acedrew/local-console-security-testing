#!/bin/bash
# Generate server certificates for config service using PKI API

set -e

PKI_URL="${PKI_URL:-http://pki-service:8000}"
API_KEY="${API_KEY:-dev-key-12345}"
SERVER_ID="config-server-01"

echo "🔐 Generating server certificates for config service..."

# Wait for PKI service to be ready
echo "⏳ Waiting for PKI service..."
until curl -sf "$PKI_URL/health" > /dev/null 2>&1; do
    sleep 2
done
echo "✅ PKI service is ready"

# Create intermediate CA if needed
echo "📝 Creating intermediate CA for $SERVER_ID..."
curl -X POST "$PKI_URL/ca/intermediate" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "{
        \"server_id\": \"$SERVER_ID\",
        \"organization\": \"AceIoT\",
        \"validity_days\": 365
    }" 2>/dev/null || echo "Intermediate CA may already exist"

# Issue server certificate with SANs for browser compatibility
echo "🎫 Issuing server certificate with SANs..."
CERT_DATA=$(curl -X POST "$PKI_URL/certificates/issue" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "{
        \"common_name\": \"config-service\",
        \"organization\": \"AceIoT\",
        \"server_id\": \"$SERVER_ID\",
        \"email\": \"config@aceiot.io\",
        \"validity_hours\": 8760,
        \"san_dns_names\": [\"localhost\", \"config-service\"],
        \"san_ip_addresses\": [\"127.0.0.1\", \"0.0.0.0\"]
    }")

# Extract certificate components
echo "$CERT_DATA" | jq -r '.certificate' > /app/certs/server.crt
echo "$CERT_DATA" | jq -r '.private_key' > /app/certs/server.key
echo "$CERT_DATA" | jq -r '.ca_chain' > /app/certs/ca-chain.crt

# Set proper permissions
chmod 600 /app/certs/server.key
chmod 644 /app/certs/server.crt /app/certs/ca-chain.crt

echo "✅ Server certificates generated:"
echo "   - Certificate: /app/certs/server.crt"
echo "   - Private Key: /app/certs/server.key"
echo "   - CA Chain: /app/certs/ca-chain.crt"

# Display certificate info
echo ""
echo "📋 Certificate Information:"
openssl x509 -in /app/certs/server.crt -noout -subject -dates -fingerprint
