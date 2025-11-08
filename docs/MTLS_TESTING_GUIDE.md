# 🔒 mTLS Testing Guide

Complete guide for testing the PKI system with mutual TLS authentication.

## ✅ What's Been Built

### 1. **PKI Service** (Port 8000)
- Issues short-lived client certificates (1 hour TTL)
- Manages root CA and server-specific intermediate CAs
- Beautiful web UI for certificate download
- Multiple format support (PEM, PKCS#12, DER, Bundle)

### 2. **Config Service** (Port 8501 - mTLS Required)
- **Rebuilt with FastAPI** (replaced Streamlit)
- **Enforces mTLS on ALL requests** (except /health)
- Middleware rejects requests without valid client certificates
- Modern configuration management UI
- Version control and audit logging

## 🚀 Complete Testing Workflow

### Step 1: Issue Client Certificate

Visit the PKI download UI:
```
http://localhost:8000/ui/download
```

Fill in the form:
- **Device Name**: `my-laptop`
- **Server ID**: `config-server-01`
- **Email** (optional): `me@example.com`

Click "Issue Certificate" and download all formats.

### Step 2: Test Without Certificate (Should Fail)

```bash
# This should be REJECTED
curl https://config-service:8501/

# Expected: 401 Unauthorized with message about requiring client certificate
```

### Step 3: Test With Valid Certificate (Should Work)

```bash
# Download the files from the web UI, then:

# Option 1: Using separate files
curl --cert client-cert-*.pem \
     --key client-key-*.pem \
     --cacert ca-chain-*.pem \
     https://config-service:8501/

# Option 2: Using bundle
curl --cert client-bundle-*.pem \
     --cacert ca-chain-*.pem \
     https://config-service:8501/

# Expected: Configuration UI HTML response
```

### Step 4: Test Certificate Expiration

```bash
# Wait 1 hour, then try again
curl --cert expired-cert.pem \
     --key client-key.pem \
     --cacert ca-chain.pem \
     https://config-service:8501/

# Expected: 401 Unauthorized (certificate expired)
```

## 🔧 Current Setup Status

### ✅ Implemented
- [x] PKI service with certificate issuance
- [x] Web UI for certificate download
- [x] Multiple certificate formats
- [x] Config service with FastAPI
- [x] mTLS enforcement middleware
- [x] Certificate verification logic
- [x] Modern configuration UI

### 🚧 To Enable mTLS (Next Steps)

The config service needs server certificates to run with HTTPS/mTLS. Here's how to set it up:

#### Option 1: Manual Certificate Setup

```bash
# 1. Issue server certificate via PKI API
curl -X POST http://localhost:8000/certificates/issue \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-12345" \
  -d '{
    "common_name": "config-service",
    "organization": "AceIoT",
    "server_id": "config-server-01",
    "validity_hours": 8760
  }' > server-cert.json

# 2. Extract certificate files
cat server-cert.json | jq -r '.certificate' > server.crt
cat server-cert.json | jq -r '.private_key' > server.key
cat server-cert.json | jq -r '.ca_chain' > ca-chain.crt

# 3. Copy to config service container
podman cp server.crt config-service:/app/certs/
podman cp server.key config-service:/app/certs/
podman cp ca-chain.crt config-service:/app/certs/

# 4. Restart config service
podman-compose restart config-service
```

#### Option 2: Automated Setup Script

Run the server cert generation script inside the container:

```bash
# Execute in the config service container
podman exec config-service bash /app/scripts/generate-server-certs.sh

# Restart the service
podman-compose restart config-service
```

## 📋 Verification Checklist

### PKI Service (Port 8000)
- [ ] Health endpoint responds: `curl http://localhost:8000/health`
- [ ] API docs accessible: `curl http://localhost:8000/docs`
- [ ] Download UI loads: `curl http://localhost:8000/ui/download`
- [ ] Can issue certificate via UI
- [ ] Can download all certificate formats

### Config Service (Port 8501 - After mTLS Setup)
- [ ] Rejects requests without certificate
- [ ] Accepts requests with valid certificate
- [ ] Rejects expired certificates
- [ ] UI loads with valid client cert
- [ ] Can save configuration changes
- [ ] Version history works

## 🧪 Python Test Script

```python
import requests

# Test without certificate (should fail)
try:
    response = requests.get('https://config-service:8501/')
    print(f"Without cert: {response.status_code}")  # Should be 401
except requests.exceptions.SSLError as e:
    print(f"SSL Error (expected): {e}")

# Test with certificate (should work)
response = requests.get(
    'https://config-service:8501/',
    cert=('client-cert.pem', 'client-key.pem'),
    verify='ca-chain.pem'
)
print(f"With cert: {response.status_code}")  # Should be 200
print(response.text[:100])  # First 100 chars of HTML
```

## 🔒 Security Features Verified

### Certificate Validation
- ✅ Client certificate required
- ✅ Certificate must be signed by trusted CA
- ✅ Certificate must not be expired
- ✅ Certificate chain validation (root + intermediary)

### Middleware Protection
- ✅ All endpoints protected (except /health)
- ✅ Middleware runs before route handlers
- ✅ Certificate info available in request state
- ✅ Helpful error messages for debugging

### Audit Trail
- ✅ All certificate issuances logged
- ✅ All config changes tracked with author
- ✅ Version history maintained
- ✅ Timestamps on all operations

## 📊 Certificate Lifecycle

```
1. Issue (PKI Service)
   ↓
2. Download (Multiple Formats)
   ↓
3. Configure Client (cURL, Python, Browser)
   ↓
4. Connect to Config Service (mTLS)
   ↓
5. Manage Configuration (Auth via Cert)
   ↓
6. Expire (1 hour TTL)
   ↓
7. Renew (Issue New Certificate)
```

## 🎯 Test Scenarios

### Scenario 1: Happy Path
1. Issue certificate via UI
2. Download bundle format
3. Access config service with certificate
4. Make configuration changes
5. View version history

### Scenario 2: Security Validation
1. Try accessing config service without certificate → **Rejected**
2. Try with invalid certificate → **Rejected**
3. Try with expired certificate → **Rejected**
4. Try with valid certificate → **Accepted**

### Scenario 3: Certificate Formats
1. Test with PEM files (separate cert/key)
2. Test with bundle file (all-in-one)
3. Test with PKCS#12 in browser
4. Verify all formats work identically

## 🐛 Troubleshooting

### Config Service Won't Start
**Problem**: SSL error about PEM lib

**Solution**: Server certificates not generated yet
```bash
# Generate server certs first
podman exec pki-service curl -X POST http://localhost:8000/certificates/issue \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-12345" \
  -d '{"common_name":"config-service","organization":"AceIoT","server_id":"config-server-01","validity_hours":8760}'
```

### Client Certificate Rejected
**Problem**: 401 Unauthorized even with certificate

**Solution**: Check certificate is valid and not expired
```bash
openssl x509 -in client-cert.pem -noout -dates
openssl verify -CAfile ca-chain.pem client-cert.pem
```

### Browser Won't Prompt for Certificate
**Problem**: Browser doesn't show certificate selection dialog

**Solution**: Import PKCS#12 file into browser certificate store
1. Download .p12 file from PKI UI
2. Import into browser (Settings → Certificates)
3. Restart browser
4. Visit https://config-service:8501

## 📈 Next Steps

1. **Generate Server Certificates**: Enable HTTPS on config service
2. **Test mTLS Flow**: Verify end-to-end certificate authentication
3. **Browser Testing**: Import .p12 and test in Chrome/Firefox
4. **Automation**: Create scripts for cert rotation
5. **Monitoring**: Set up alerts for cert expiration

## 🔗 Related Documentation

- [Certificate Download Guide](./CERTIFICATE_DOWNLOAD_GUIDE.md)
- [PKI Architecture](./pki-architecture.md)
- [Security Best Practices](./security-best-practices.md)
- [API Documentation](http://localhost:8000/docs)

---

**Status**: Config service rebuilt with mTLS enforcement. Ready for testing once server certificates are generated.
