# 🔐 Certificate Download and Usage Guide

This guide explains how to use the PKI service's certificate download UI and how to use the certificates with HTTP clients.

## 📥 Downloading Certificates

### Web UI (Easiest)

1. **Open the download interface:**
   ```
   http://localhost:8000/ui/download
   ```

2. **Fill out the form:**
   - **Device/Client Name**: e.g., `my-laptop`, `device-001`
   - **Email** (optional): e.g., `device@example.com`
   - **Server ID**: The config server you'll connect to, e.g., `config-server-01`

3. **Click "Issue Certificate"**
   - You'll be redirected to a download page
   - Certificate is valid for **1 hour** by default

4. **Download in your preferred format:**
   - **PEM**: Separate cert and key files (most common)
   - **PKCS#12 (.p12)**: Single file for browsers/Windows
   - **Bundle**: All-in-one file with cert + key + CA chain
   - **DER**: Binary format for some applications

### API Method

```bash
# Issue certificate via API
curl -X POST http://localhost:8000/certificates/issue \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key-here" \
  -d '{
    "common_name": "my-device",
    "organization": "AceIoT",
    "server_id": "config-server-01",
    "email": "device@example.com",
    "validity_hours": 1
  }'
```

## 📦 Available Certificate Formats

| Format | Extension | Use Case | How to Download |
|--------|-----------|----------|-----------------|
| **PEM** | `.pem`, `.crt`, `.key` | Linux/macOS, most HTTP clients | Individual downloads or bundle |
| **PKCS#12** | `.p12`, `.pfx` | Windows, browsers | Single password-protected file |
| **DER** | `.der` | Java applications | Binary certificate format |
| **Bundle** | `.bundle.pem` | Quick setup | Combined cert + key + CA chain |

## 🌐 Using Certificates with HTTP Clients

### cURL

**Option 1: Separate files**
```bash
curl --cert client-cert.pem \
     --key client-key.pem \
     --cacert ca-chain.pem \
     https://config-server:8501
```

**Option 2: Bundle file**
```bash
curl --cert client-bundle.pem \
     --cacert ca-chain.pem \
     https://config-server:8501
```

**Option 3: PKCS#12 file**
```bash
# Convert .p12 to PEM first
openssl pkcs12 -in client.p12 -out client.pem -nodes

curl --cert client.pem https://config-server:8501
```

### Python `requests`

```python
import requests

# Method 1: Separate cert and key
response = requests.get(
    'https://config-server:8501',
    cert=('client-cert.pem', 'client-key.pem'),
    verify='ca-chain.pem'
)

# Method 2: Bundle file
response = requests.get(
    'https://config-server:8501',
    cert='client-bundle.pem',
    verify='ca-chain.pem'
)

# Method 3: Custom SSL context
import ssl
import urllib.request

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_cert_chain('client-cert.pem', 'client-key.pem')
context.load_verify_locations('ca-chain.pem')

response = urllib.request.urlopen(
    'https://config-server:8501',
    context=context
)
```

### Node.js `axios`

```javascript
const axios = require('axios');
const fs = require('fs');
const https = require('https');

const httpsAgent = new https.Agent({
  cert: fs.readFileSync('client-cert.pem'),
  key: fs.readFileSync('client-key.pem'),
  ca: fs.readFileSync('ca-chain.pem')
});

axios.get('https://config-server:8501', { httpsAgent })
  .then(response => console.log(response.data))
  .catch(error => console.error(error));
```

### wget

```bash
wget --certificate=client-cert.pem \
     --private-key=client-key.pem \
     --ca-certificate=ca-chain.pem \
     https://config-server:8501
```

### Browsers (Chrome, Firefox, Safari)

1. **Download the PKCS#12 (.p12) file**
   - Optionally set a password during download

2. **Import into browser:**

   **Chrome/Edge:**
   - Settings → Privacy and security → Security → Manage certificates
   - Import → Select `.p12` file → Enter password
   - Restart browser

   **Firefox:**
   - Settings → Privacy & Security → Certificates → View Certificates
   - Your Certificates → Import → Select `.p12` file
   - Enter password

   **Safari (macOS):**
   - Double-click the `.p12` file
   - Keychain Access opens → Enter password
   - Certificate is added to login keychain

3. **Visit the config server**
   - Browser will prompt to select a certificate
   - Choose the imported certificate

## ⚙️ Advanced Usage

### Convert Between Formats

**PEM to PKCS#12:**
```bash
openssl pkcs12 -export \
  -out client.p12 \
  -inkey client-key.pem \
  -in client-cert.pem \
  -certfile ca-chain.pem \
  -name "My Client Certificate"
```

**PKCS#12 to PEM:**
```bash
# Extract certificate
openssl pkcs12 -in client.p12 -out client-cert.pem -clcerts -nokeys

# Extract private key
openssl pkcs12 -in client.p12 -out client-key.pem -nocerts -nodes

# Extract CA chain
openssl pkcs12 -in client.p12 -out ca-chain.pem -cacerts -nokeys
```

**PEM to DER:**
```bash
openssl x509 -in client-cert.pem -outform DER -out client-cert.der
```

### Inspect Certificates

**View certificate details:**
```bash
openssl x509 -in client-cert.pem -text -noout
```

**Check expiration:**
```bash
openssl x509 -in client-cert.pem -noout -dates
```

**Verify certificate chain:**
```bash
openssl verify -CAfile ca-chain.pem client-cert.pem
```

**Check certificate fingerprint:**
```bash
openssl x509 -in client-cert.pem -noout -fingerprint -sha256
```

### Test mTLS Connection

**Test with OpenSSL:**
```bash
openssl s_client \
  -connect config-server:8501 \
  -cert client-cert.pem \
  -key client-key.pem \
  -CAfile ca-chain.pem \
  -showcerts
```

## 🔒 Security Best Practices

### Certificate Storage

✅ **DO:**
- Store private keys with `chmod 600` permissions
- Keep certificates in `~/.ssh/` or `~/.certs/`
- Use password protection for PKCS#12 files
- Delete certificates after they expire

❌ **DON'T:**
- Commit private keys to version control
- Share private keys via email/chat
- Store keys in world-readable locations
- Reuse the same certificate on multiple devices

### Certificate Lifecycle

1. **Issue**: Download certificate immediately after creation
2. **Use**: Configure your HTTP client within 1 hour
3. **Monitor**: Check expiration time (certificates are short-lived)
4. **Renew**: Request new certificate before expiration
5. **Revoke**: Delete old certificates after renewal

## 📊 Certificate Metadata

Each certificate includes:

| Field | Example | Description |
|-------|---------|-------------|
| **Common Name** | `device-001` | Your device identifier |
| **Organization** | `AceIoT` | Organization name |
| **Issuer** | `Intermediate CA - config-server-01` | Signing CA |
| **Serial Number** | `123456789` | Unique certificate ID |
| **Valid From** | `2025-11-08 16:30:00 UTC` | Start of validity |
| **Valid Until** | `2025-11-08 17:30:00 UTC` | Expiration time |
| **Fingerprint** | `AA:BB:CC:...` | SHA-256 hash |

## 🚨 Troubleshooting

### "Certificate expired" Error

**Cause**: Certificate TTL is 1 hour
**Solution**: Issue a new certificate

```bash
# Check expiration
openssl x509 -in client-cert.pem -noout -dates
```

### "Certificate verify failed" Error

**Cause**: CA chain not trusted
**Solution**: Ensure you're using the correct `ca-chain.pem` file

```bash
# Verify certificate against CA
openssl verify -CAfile ca-chain.pem client-cert.pem
```

### "Permission denied" on Private Key

**Cause**: Incorrect file permissions
**Solution**: Fix permissions

```bash
chmod 600 client-key.pem
```

### Browser Doesn't Show Certificate Prompt

**Cause**: Certificate not properly imported
**Solution**: Re-import the `.p12` file and restart browser

## 📝 Example Workflow

### Full End-to-End Example

```bash
# 1. Issue certificate
curl -X POST http://localhost:8000/ui/download/issue \
  -d "common_name=my-laptop" \
  -d "server_id=config-server-01" \
  -d "email=me@example.com"

# 2. Download files (save the cert_id from response)
CERT_ID="123456789"
curl -o client-cert.pem "http://localhost:8000/ui/download/$CERT_ID/pem"
curl -o client-key.pem "http://localhost:8000/ui/download/$CERT_ID/key"
curl -o ca-chain.pem "http://localhost:8000/ui/download/$CERT_ID/ca-chain"

# 3. Set permissions
chmod 600 client-key.pem
chmod 644 client-cert.pem ca-chain.pem

# 4. Test connection
curl --cert client-cert.pem \
     --key client-key.pem \
     --cacert ca-chain.pem \
     https://config-server:8501

# 5. Use with Python
python3 << 'EOF'
import requests
response = requests.get(
    'https://config-server:8501',
    cert=('client-cert.pem', 'client-key.pem'),
    verify='ca-chain.pem'
)
print(f"Status: {response.status_code}")
print(response.text)
EOF
```

## 🔗 Related Documentation

- [PKI Architecture](./pki-architecture.md)
- [Security Best Practices](./security-best-practices.md)
- [API Documentation](http://localhost:8000/docs)
- [Deployment Guide](./README.md)

---

**Need Help?** Check the API documentation at `http://localhost:8000/docs` or file an issue.
