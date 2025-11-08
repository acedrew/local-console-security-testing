# 🚀 Quick Start Guide - mTLS PKI System

## System Status: ✅ OPERATIONAL

Your PKI system with mutual TLS authentication is now fully operational!

## Services Running

### 1. PKI Service (Port 8000)
- **URL**: http://localhost:8000
- **Health**: http://localhost:8000/health
- **Download UI**: http://localhost:8000/ui/download
- **API Docs**: http://localhost:8000/docs

### 2. Config Service (Port 8501 - mTLS Required)
- **URL**: https://localhost:8501
- **Requires**: Valid client certificate issued by PKI service
- **Certificate TTL**: 1 hour (short-lived, no revocation needed)

## 🎯 Quick Test

```bash
# 1. Issue a client certificate
curl -X POST http://localhost:8000/certificates/issue \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-12345" \
  -d '{
    "common_name": "my-device",
    "organization": "AceIoT",
    "server_id": "config-server-01",
    "email": "me@example.com",
    "validity_hours": 1
  }' | jq -r '.certificate' > cert.pem

# Extract private key
curl -X POST http://localhost:8000/certificates/issue \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-12345" \
  -d '{
    "common_name": "my-device",
    "organization": "AceIoT",
    "server_id": "config-server-01",
    "email": "me@example.com",
    "validity_hours": 1
  }' | jq -r '.private_key' > key.pem

# Extract CA chain
curl -X POST http://localhost:8000/certificates/issue \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-12345" \
  -d '{
    "common_name": "my-device",
    "organization": "AceIoT",
    "server_id": "config-server-01",
    "email": "me@example.com",
    "validity_hours": 1
  }' | jq -r '.ca_chain' > ca-chain.pem

# 2. Access config service with certificate
curl --cert cert.pem \
     --key key.pem \
     --cacert ca-chain.pem \
     https://localhost:8501/api/config
```

## 🌐 Web UI Method (Easiest)

1. Visit: **http://localhost:8000/ui/download**
2. Fill in the form:
   - **Device Name**: `my-laptop`
   - **Server ID**: `config-server-01`
   - **Email** (optional): `your-email@example.com`
3. Click **Issue Certificate**
4. Download all certificate formats
5. Use the downloaded files with curl or your browser

## 📋 Certificate Formats Available

### Via Web UI Download:

- **`client-cert-*.pem`**: Certificate (PEM)
- **`client-key-*.pem`**: Private key (PEM)
- **`ca-chain-*.pem`**: CA certificate chain (PEM)
- **`client-bundle-*.pem`**: All-in-one bundle (cert + key)
- **`client-cert-*.p12`**: PKCS#12 format (for browsers/Windows)
- **`client-cert-*.der`**: DER format
- **`full-bundle-*.pem`**: Complete bundle (cert + key + CA chain)

## 🔧 Usage Examples

### cURL (Separate Files)
```bash
curl --cert client-cert-*.pem \
     --key client-key-*.pem \
     --cacert ca-chain-*.pem \
     https://localhost:8501/
```

### cURL (Bundle File)
```bash
curl --cert client-bundle-*.pem \
     --cacert ca-chain-*.pem \
     https://localhost:8501/
```

### Python (requests)
```python
import requests

response = requests.get(
    'https://localhost:8501/api/config',
    cert=('client-cert.pem', 'client-key.pem'),
    verify='ca-chain.pem'
)
print(response.json())
```

### Node.js (https)
```javascript
const https = require('https');
const fs = require('fs');

const options = {
    hostname: 'localhost',
    port: 8501,
    path: '/api/config',
    method: 'GET',
    cert: fs.readFileSync('client-cert.pem'),
    key: fs.readFileSync('client-key.pem'),
    ca: fs.readFileSync('ca-chain.pem')
};

https.request(options, (res) => {
    res.on('data', (d) => process.stdout.write(d));
}).end();
```

### Browser (Chrome/Firefox)

**🍎 macOS Users**: Chrome on macOS requires special setup. See [macOS Setup Guide](./MACOS_SETUP.md).

**Quick macOS Setup**:
```bash
# 1. Download P12 from http://localhost:8000/ui/download
# 2. Run the helper script:
./scripts/macos-cert-import.sh full-setup ~/Downloads/client-*.p12
# 3. Restart Chrome completely (Cmd+Q), then visit https://localhost:8501
```

**Other Platforms**:
1. Download the **`.p12`** file
2. Open browser settings → Certificates
3. Import the `.p12` file (no password required)
4. Visit: https://localhost:8501
5. Browser will prompt you to select the certificate

## 🔒 Security Features

### ✅ What's Enforced:

- **Client certificate required** on ALL config service requests
- **Certificate chain validation** (root CA + intermediate CA)
- **Certificate expiration** checked (1-hour TTL)
- **TLS 1.3** encryption
- **No revocation needed** (certificates expire quickly)

### ❌ What's Rejected:

- Requests without client certificate
- Expired certificates
- Certificates signed by wrong CA
- Certificates for wrong server_id

## 📊 Architecture

```
┌─────────────────┐
│   PKI Service   │ (Port 8000)
│   (HTTP)        │
└────────┬────────┘
         │
         │ Issues certificates
         │
         ▼
┌─────────────────────────────┐
│  Root CA                    │
│  └─ Intermediate CA         │
│     (config-server-01)      │
│     └─ Client Certificates  │
└─────────────────────────────┘
         │
         │ Authenticates with
         │
         ▼
┌─────────────────┐
│ Config Service  │ (Port 8501)
│ (HTTPS + mTLS)  │
└─────────────────┘
```

## 🧪 Testing

Run the automated test suite:
```bash
./tests/test_mtls_workflow.sh
```

## 📚 Additional Documentation

- [Complete Testing Guide](./MTLS_TESTING_GUIDE.md)
- [Certificate Download Guide](./CERTIFICATE_DOWNLOAD_GUIDE.md)
- [PKI Architecture](../README.md)

## 🎓 Key Concepts

### Short-Lived Certificates
- **TTL**: 1 hour by default
- **Why**: Eliminates need for complex CRL/OCSP
- **How**: Request new cert when needed (< 60 seconds)

### Dual Verification
- **Root CA**: Trust anchor for the entire PKI
- **Intermediate CA**: Server-specific CA (one per server_id)
- **Client Cert**: Must be signed by the correct intermediate CA

### Server-Specific CAs
- Each config server gets its own intermediate CA
- Certificates for `config-server-01` won't work on `config-server-02`
- Provides logical isolation between servers

---

**Status**: Production-ready prototype ✅
**Last Updated**: 2025-11-08
**Version**: 3.0.0
