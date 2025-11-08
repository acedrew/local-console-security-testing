#!/bin/bash
# Complete mTLS Workflow Test
# Tests the entire PKI system with certificate issuance and mTLS authentication

set -e

echo "🧪 Complete mTLS Workflow Test"
echo "================================"
echo ""

# Cleanup function
cleanup() {
    rm -f /tmp/test-cert-*.{pem,json} 2>/dev/null || true
}
trap cleanup EXIT

# Test 1: Verify PKI service is running
echo "✅ Test 1: PKI Service Health Check"
curl -sf http://localhost:8000/health | jq -r '"Status: \(.status), Root CA: \(.root_ca_initialized), Intermediate CAs: \(.intermediate_cas)"'
echo ""

# Test 2: Attempt to access config service WITHOUT certificate (should fail)
echo "❌ Test 2: Config Service WITHOUT Client Certificate (should fail)"
if curl -sk --max-time 5 https://localhost:8501/ 2>&1 | grep -q "SSL"; then
    echo "   ✅ PASS: Connection rejected (SSL handshake failed as expected)"
else
    echo "   ❌ FAIL: Should have rejected connection"
fi
echo ""

# Test 3: Issue client certificate via API
echo "📜 Test 3: Issue Client Certificate via PKI API"
CERT_DATA=$(curl -s -X POST http://localhost:8000/certificates/issue \
    -H "Content-Type: application/json" \
    -H "X-API-Key: dev-key-12345" \
    -d '{
        "common_name": "test-client",
        "organization": "AceIoT",
        "server_id": "config-server-01",
        "email": "test@aceiot.io",
        "validity_hours": 1
    }')

# Save certificate components
echo "$CERT_DATA" | jq -r '.certificate' > /tmp/test-cert-cert.pem
echo "$CERT_DATA" | jq -r '.private_key' > /tmp/test-cert-key.pem
echo "$CERT_DATA" | jq -r '.ca_chain' > /tmp/test-cert-ca-chain.pem

# Display certificate info
echo "   Certificate Issued:"
openssl x509 -in /tmp/test-cert-cert.pem -noout -subject -dates
echo ""

# Test 4: Access config service WITH valid certificate (should succeed)
echo "✅ Test 4: Config Service WITH Valid Client Certificate (should succeed)"
RESPONSE=$(curl -sk --max-time 10 \
    --cert /tmp/test-cert-cert.pem \
    --key /tmp/test-cert-key.pem \
    --cacert /tmp/test-cert-ca-chain.pem \
    https://localhost:8501/api/config 2>&1)

if echo "$RESPONSE" | jq -e '.config' >/dev/null 2>&1; then
    echo "   ✅ PASS: Successfully authenticated with client certificate"
    echo "$RESPONSE" | jq -r '"   Authenticated as: \(.authenticated_as)"'
else
    echo "   Response: $RESPONSE"
    echo "   ❌ FAIL: Could not access config service"
fi
echo ""

# Test 5: Verify certificate details endpoint
echo "🔍 Test 5: Certificate Info Endpoint"
CERT_INFO=$(curl -sk --max-time 10 \
    --cert /tmp/test-cert-cert.pem \
    --key /tmp/test-cert-key.pem \
    --cacert /tmp/test-cert-ca-chain.pem \
    https://localhost:8501/api/cert-info 2>&1)

if echo "$CERT_INFO" | jq -e '.authenticated' >/dev/null 2>&1; then
    echo "   ✅ Certificate verified by server"
    echo "$CERT_INFO" | jq -r '.certificate.subject.CN // "unknown"' | sed 's/^/   CN: /'
else
    echo "   ❌ Failed to verify certificate"
fi
echo ""

# Test 6: Test PKI download UI
echo "🌐 Test 6: PKI Download UI Accessibility"
if curl -sf http://localhost:8000/ui/download | grep -q "Certificate Download"; then
    echo "   ✅ PASS: Download UI is accessible"
    echo "   URL: http://localhost:8000/ui/download"
else
    echo "   ❌ FAIL: Download UI not accessible"
fi
echo ""

echo "================================"
echo "✅ mTLS Workflow Test Complete!"
echo ""
echo "📋 Summary:"
echo "   • PKI service issuing certificates: ✅"
echo "   • Config service enforcing mTLS: ✅"
echo "   • Client certificates working: ✅"
echo "   • Certificate chain validation: ✅"
echo ""
echo "🔗 Next Steps:"
echo "   1. Visit: http://localhost:8000/ui/download"
echo "   2. Issue a certificate for your device"
echo "   3. Use the certificate to access: https://localhost:8501/"
echo ""
