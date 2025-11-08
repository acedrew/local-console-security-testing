#!/bin/bash
# Test P12 import and verify it's suitable for client authentication

set -e

echo "🧪 Testing P12 Certificate Import for macOS Chrome"
echo "==================================================="
echo ""

# Issue a test certificate
echo "📜 Issuing test certificate..."
CERT_DATA=$(curl -s -X POST http://localhost:8000/certificates/issue \
    -H "Content-Type: application/json" \
    -H "X-API-Key: dev-key-12345" \
    -d '{
        "common_name": "macos-test-cert",
        "organization": "AceIoT",
        "server_id": "config-server-01",
        "email": "test@macos.local",
        "validity_hours": 24
    }')

SERIAL=$(echo "$CERT_DATA" | jq -r '.serial_number')
echo "   Serial: $SERIAL"

# Save files
echo "$CERT_DATA" | jq -r '.certificate' > /tmp/test-cert.pem
echo "$CERT_DATA" | jq -r '.private_key' > /tmp/test-key.pem
echo "$CERT_DATA" | jq -r '.ca_chain' > /tmp/test-ca-chain.pem

# Create P12 file
echo ""
echo "📦 Creating P12 file..."
openssl pkcs12 -export \
    -in /tmp/test-cert.pem \
    -inkey /tmp/test-key.pem \
    -certfile /tmp/test-ca-chain.pem \
    -out ~/Downloads/aceiot-test-client.p12 \
    -name "AceIoT Test Client (macOS)" \
    -passout pass:

echo "   ✅ P12 created: ~/Downloads/aceiot-test-client.p12"

# Verify P12 contents
echo ""
echo "🔍 Verifying P12 Contents..."
openssl pkcs12 -in ~/Downloads/aceiot-test-client.p12 -nodes -passin pass: | \
    openssl x509 -noout -subject -dates -ext extendedKeyUsage

echo ""
echo "📋 Checking for private key in P12..."
if openssl pkcs12 -in ~/Downloads/aceiot-test-client.p12 -nodes -passin pass: | \
    grep -q "BEGIN PRIVATE KEY\|BEGIN RSA PRIVATE KEY"; then
    echo "   ✅ Private key found in P12"
else
    echo "   ❌ Private key NOT found in P12"
    exit 1
fi

echo ""
echo "📋 Certificate chain in P12:"
openssl pkcs12 -in ~/Downloads/aceiot-test-client.p12 -nodes -passin pass: -cacerts -nokeys 2>/dev/null | \
    grep "subject=" | wc -l | xargs echo "   Number of CA certificates:"

echo ""
echo "==================================================="
echo "✅ P12 file is ready for import"
echo ""
echo "📌 Next Steps for macOS Chrome:"
echo ""
echo "1. Import into Login Keychain (USER-specific, not System):"
echo "   security import ~/Downloads/aceiot-test-client.p12 \\"
echo "     -k ~/Library/Keychains/login.keychain-db \\"
echo "     -T /Applications/Google\ Chrome.app \\"
echo "     -T /Applications/Safari.app \\"
echo "     -A"
echo ""
echo "2. The -A flag makes the key always accessible (no prompt)"
echo "   The -T flags allow Chrome and Safari to use the key"
echo ""
echo "3. Verify import:"
echo "   security find-identity -v -p codesigning ~/Library/Keychains/login.keychain-db | grep AceIoT"
echo ""
echo "4. Restart Chrome COMPLETELY (Cmd+Q)"
echo ""
echo "5. Visit: https://localhost:8501"
echo ""
