# mTLS PKI System - Complete Workflow Documentation

**Version:** 2.0.0
**Last Updated:** 2025-11-08
**Status:** Production-Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Certificate Format Requirements](#certificate-format-requirements)
4. [Security Workflow](#security-workflow)
5. [Platform-Specific Requirements](#platform-specific-requirements)
6. [API Reference](#api-reference)
7. [Troubleshooting](#troubleshooting)

---

## Overview

This system implements a production-grade mutual TLS (mTLS) authentication infrastructure with short-lived certificates, automatic server-specific intermediate CAs, and comprehensive client certificate management.

### Key Features

- ✅ **Three-Tier PKI Hierarchy**: Root CA → Intermediate CA → Client/Server Certificates
- ✅ **Server-Specific Intermediate CAs**: Automatic isolation per service
- ✅ **Short-Lived Certificates**: 1-hour default TTL for clients, configurable up to 10 years for servers
- ✅ **Multiple Certificate Formats**: PEM, DER, PKCS#12, bundle formats
- ✅ **Modern Browser Compatibility**: Subject Alternative Names (SANs) support
- ✅ **Platform-Optimized**: Special handling for macOS Keychain requirements
- ✅ **Secure P12 Encryption**: Auto-generated random passwords for macOS compatibility
- ✅ **Web UI**: User-friendly certificate issuance and download interface

### Use Cases

- Local development with production-like mTLS security
- Microservices authentication testing
- Client certificate authentication workflows
- Certificate rotation testing
- Multi-platform certificate deployment validation

---

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     PKI Service (Port 8000)                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Root CA (AceIoT Root CA)                              │ │
│  │  - RSA 4096-bit key                                    │ │
│  │  - 10-year validity                                    │ │
│  │  - Self-signed                                         │ │
│  └────────────────┬───────────────────────────────────────┘ │
│                   │ signs                                    │
│  ┌────────────────▼───────────────────────────────────────┐ │
│  │  Intermediate CA (per server)                          │ │
│  │  - Server-specific (e.g., config-server-01)           │ │
│  │  - RSA 2048-bit key                                    │ │
│  │  - 5-year validity                                     │ │
│  │  - PathLen:0 (can't sign other CAs)                   │ │
│  └────────────────┬───────────────────────────────────────┘ │
│                   │ signs                                    │
│  ┌────────────────▼───────────────────────────────────────┐ │
│  │  Client/Server Certificates                            │ │
│  │  - RSA 2048-bit key                                    │ │
│  │  - Short-lived (1 hour default, up to 10 years)       │ │
│  │  - Extended Key Usage: CLIENT_AUTH or SERVER_AUTH     │ │
│  │  - Optional SANs for server certs                      │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   Config Service (Port 8501)                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  mTLS Enforcement                                      │ │
│  │  - Requires valid client certificate                   │ │
│  │  - Validates against CA chain                          │ │
│  │  - Checks certificate is not expired                   │ │
│  │  - Verifies Extended Key Usage                         │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Certificate Chain Structure

```
Root CA (self-signed)
  |
  ├─── Intermediate CA: config-server-01
  |      ├─── Server Certificate (config-service)
  |      ├─── Client Certificate (user-1)
  |      ├─── Client Certificate (user-2)
  |      └─── Client Certificate (user-N)
  |
  └─── Intermediate CA: auth-server-01
         ├─── Server Certificate (auth-service)
         └─── Client Certificates...
```

---

## Certificate Format Requirements

### Critical Requirements Discovered

Through testing across platforms (especially macOS Chrome), we discovered several critical requirements:

#### 1. **Subject Alternative Names (SANs) - REQUIRED for Server Certificates**

Modern browsers (Chrome, Firefox, Safari) **reject** server certificates without SANs, even if the Common Name (CN) matches.

**❌ Wrong** (CN-only):
```
Subject: CN=config-service, O=AceIoT, C=US
```

**✅ Correct** (CN + SANs):
```
Subject: CN=config-service, O=AceIoT, C=US
X509v3 Subject Alternative Name:
    DNS:localhost
    DNS:config-service
    IP:127.0.0.1
    IP:0.0.0.0
```

**Why:** RFC 6125 deprecated CN-based hostname verification. All modern browsers require SANs.

**Implementation:**
```python
# Server certificate MUST include SANs
san_dns_names = ["localhost", "config-service"]
san_ip_addresses = ["127.0.0.1", "0.0.0.0"]

cert = X509Utils.create_client_certificate(
    common_name="config-service",
    san_dns_names=san_dns_names,
    san_ip_addresses=san_ip_addresses,
    # ... other params
)
```

#### 2. **Extended Key Usage (EKU) - REQUIRED**

Certificates MUST have the correct Extended Key Usage extension:

**Server Certificates:**
```
X509v3 Extended Key Usage: critical
    TLS Web Server Authentication
    TLS Web Client Authentication  # Optional, for mTLS
```

**Client Certificates:**
```
X509v3 Extended Key Usage: critical
    TLS Web Client Authentication
```

**Why:** Browsers and TLS libraries check EKU to prevent certificate misuse.

**Implementation:**
```python
# Server cert (with SANs)
if san_dns_names or san_ip_addresses:
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        ]),
        critical=True,
    )
else:
    # Client-only cert (no SANs)
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        ]),
        critical=True,
    )
```

#### 3. **PKCS#12 Encryption - REQUIRED for macOS**

macOS `security` command **requires** P12 files to be password-protected. Unencrypted P12 files fail with:

```
security: SecKeychainItemImport: MAC verification failed during PKCS12 import (wrong password?)
```

**Solution:** Auto-generate random password per certificate:

```python
import secrets
import string

# Generate cryptographically secure 12-character password
p12_password = ''.join(
    secrets.choice(string.ascii_letters + string.digits)
    for _ in range(12)
)

# Use password when creating P12
p12_data = format_converter.pem_to_pkcs12(
    cert_pem=cert_bytes,
    key_pem=key_bytes,
    ca_chain_pem=ca_chain_bytes,
    password=p12_password.encode(),
    friendly_name=b"AceIoT Client Certificate"
)
```

**Display to User:** Password must be prominently shown on download page for user to copy and use during import.

#### 4. **Private Key Association - REQUIRED for Client Certs**

For Chrome (especially macOS) to recognize a certificate as usable for client authentication:

- Certificate MUST be in **Login Keychain** (not System)
- Certificate MUST have an **associated private key** (identity)
- Private key MUST be **accessible** to Chrome

**macOS Keychain Categories:**
- **"Certificates"** - Shows all certificates (including CAs without keys)
- **"My Certificates"** - Shows certificates WITH private keys (identities)

**Chrome only uses certificates from "My Certificates"**

**Verification:**
```bash
# Check for identities (cert + private key)
security find-identity -v ~/Library/Keychains/login.keychain-db | grep -i aceiot

# Should show:
# 1) ABC123... "AceIoT Client Certificate (12345)"
```

#### 5. **macOS `-A` Flag - REQUIRED for Seamless Chrome Access**

When importing P12 on macOS, the `-A` flag is critical:

```bash
security import client.p12 \
  -k ~/Library/Keychains/login.keychain-db \
  -T /Applications/Google\ Chrome.app \
  -A  # Always accessible - CRITICAL!
```

**What `-A` does:**
- Makes private key accessible to all applications without prompting
- Required for Chrome to see the certificate in selection dialog
- Without it, Chrome won't show the certificate

**Trade-off:** Requires macOS login password during import

#### 6. **Certificate Chain in P12 - REQUIRED**

P12 files MUST include the complete CA chain:

```
P12 Contents:
├── Client Certificate
├── Private Key
├── Intermediate CA Certificate  # REQUIRED
└── Root CA Certificate          # REQUIRED
```

**Why:** Clients need the full chain to validate the certificate up to a trusted root.

**Implementation:**
```python
ca_chain_pem = (
    intermediate_ca_cert_pem +
    root_ca_cert_pem
)

p12_data = pem_to_pkcs12(
    cert_pem=client_cert_pem,
    key_pem=private_key_pem,
    ca_chain_pem=ca_chain_pem,  # Full chain
    # ...
)
```

---

## Security Workflow

### 1. Initial Setup

#### Start Services

```bash
# Start PKI and Config services
podman-compose up -d

# Verify services are healthy
curl http://localhost:8000/health
curl http://localhost:8501/health  # Will fail - needs cert!
```

#### Initialize PKI (Automatic)

On first startup, the PKI service automatically:
1. Generates Root CA (if not exists)
2. Persists to `/app/data/root-ca/`
3. Exposes via API at `/ca/root`

### 2. Server Certificate Issuance

#### Generate Server Certificate with SANs

```bash
# Using the helper script (recommended)
./scripts/generate-server-certs.sh

# Or manually via API
curl -X POST http://localhost:8000/certificates/issue \
  -H "Content-Type: application/json" \
  -H "X-API-Key: super-secret-key-change-in-production" \
  -d '{
    "common_name": "config-service",
    "organization": "AceIoT",
    "server_id": "config-server-01",
    "email": "config@aceiot.io",
    "validity_hours": 8760,
    "san_dns_names": ["localhost", "config-service"],
    "san_ip_addresses": ["127.0.0.1", "0.0.0.0"]
  }'
```

**Important:**
- Always include SANs for server certificates
- Include all DNS names and IPs the service will be accessed from
- Validity can be longer for servers (up to 10 years)

#### Deploy Server Certificate

The `generate-server-certs.sh` script automatically:
1. Creates intermediate CA for server
2. Issues server certificate with SANs
3. Saves to `config/certs/server/`
4. Triggers config service restart

### 3. Client Certificate Issuance

#### Via Web UI (Recommended)

1. **Visit:** http://localhost:8000/ui/download
2. **Fill form:**
   - Common Name: `user@example.com` or `user-device-123`
   - Organization: `AceIoT`
   - Server ID: `config-server-01` (must match server)
   - Email: `user@example.com` (optional)
   - Validity: `1` hour (default, adjust as needed)

3. **Download page shows:**
   - Certificate details
   - **P12 Password** (12-character random password) - COPY THIS!
   - Download buttons for all formats

4. **Download files:**
   - **PKCS#12 (.p12)** - For browsers (Chrome, Safari)
   - **PEM** - For curl, Python, other tools
   - **CA Chain** - For verification

#### Via API

```bash
curl -X POST http://localhost:8000/certificates/issue \
  -H "Content-Type: application/json" \
  -H "X-API-Key: super-secret-key-change-in-production" \
  -d '{
    "common_name": "user@example.com",
    "organization": "AceIoT",
    "server_id": "config-server-01",
    "email": "user@example.com",
    "validity_hours": 1
  }'

# Response includes download links for all formats
```

### 4. Client Certificate Installation

#### macOS (Chrome/Safari)

**Prerequisites:**
- P12 file downloaded
- P12 password copied from download page

**Installation Steps:**

```bash
# 1. Trust the Root CA
./scripts/macos-cert-import.sh trust

# 2. Import P12 file
./scripts/macos-cert-import.sh import ~/Downloads/client-*.p12

# You'll see TWO prompts:
# Prompt 1: "Enter Import Password" → Enter P12 password from download page
# Prompt 2: "Enter password for keychain" → Enter your Mac login password

# 3. Verify installation
./scripts/macos-cert-import.sh verify

# Should show:
# ✅ Root CA found in Login Keychain
# ✅ Client certificate(s) with private keys found!

# 4. Restart Chrome COMPLETELY
osascript -e 'quit app "Google Chrome"'
sleep 2
open -a "Google Chrome"
```

**Important:**
- Import to **Login Keychain** (not System)
- Use `-A` flag for Chrome access
- Restart Chrome completely (Cmd+Q, not just close window)

#### Linux

```bash
# Import P12 into NSS database (for Chrome/Firefox)
pk12util -i client.p12 -d sql:$HOME/.pki/nssdb

# Or convert to PEM for system-wide trust
openssl pkcs12 -in client.p12 -out client.pem -nodes
openssl pkcs12 -in client.p12 -out key.pem -nocerts -nodes
```

#### Windows

```powershell
# Import P12 to Current User store
Import-PfxCertificate -FilePath client.p12 `
  -CertStoreLocation Cert:\CurrentUser\My `
  -Password (ConvertTo-SecureString -String "p12password" -AsPlainText -Force)
```

### 5. Testing mTLS Connection

#### Browser (Chrome)

1. Visit: **https://localhost:8501**
2. Chrome prompts: "Select a certificate"
3. Choose your certificate (e.g., "AceIoT Client Certificate (12345)")
4. Click "OK"
5. Page loads successfully ✅

**Troubleshooting:**
- No certificate shown? Check Keychain Access → My Certificates
- Certificate shown but error? Check it's not expired (1-hour TTL)
- Connection refused? Verify server is running and has valid cert

#### Command Line (curl)

```bash
# Using PEM format
curl --cert config/certs/client/cert.pem \
     --key config/certs/client/key.pem \
     --cacert config/certs/client/ca-chain.pem \
     https://localhost:8501

# Using P12 format (requires password)
curl --cert-type P12 \
     --cert client.p12:p12password \
     https://localhost:8501
```

#### Python (requests)

```python
import requests

response = requests.get(
    'https://localhost:8501',
    cert=('client.pem', 'key.pem'),
    verify='ca-chain.pem'
)

print(response.status_code)  # 200
print(response.json())
```

### 6. Certificate Rotation

#### Client Certificate Renewal

Since client certificates have short TTLs (1 hour default):

1. Visit UI: http://localhost:8000/ui/download
2. Issue new certificate (same process as before)
3. Download new P12 with new password
4. Import new certificate (can coexist with old)
5. Old certificate expires automatically

#### Server Certificate Renewal

```bash
# Regenerate with new validity period
./scripts/generate-server-certs.sh

# Config service automatically restarts with new certificate
```

---

## Platform-Specific Requirements

### macOS Keychain Requirements

#### Critical Findings

1. **Login Keychain vs System Keychain**
   - Chrome ONLY checks Login Keychain
   - System Keychain certificates are ignored
   - Always import to: `~/Library/Keychains/login.keychain-db`

2. **"My Certificates" vs "Certificates"**
   - "Certificates": All certs including CAs (no private key)
   - "My Certificates": Certs WITH private keys (identities)
   - Chrome only uses entries from "My Certificates"

3. **Private Key Access Control**
   - Default import restricts key access per application
   - `-A` flag makes key always accessible (required for Chrome)
   - `-T /Applications/Google\ Chrome.app` adds Chrome to ACL

4. **Password Requirements**
   - First prompt: P12 file password (from download page)
   - Second prompt: macOS login password (for `-A` flag)

#### Verification Commands

```bash
# List identities (cert + key) in Login Keychain
security find-identity -v ~/Library/Keychains/login.keychain-db

# List all certificates in Login Keychain
security find-certificate -a ~/Library/Keychains/login.keychain-db

# Export certificate for inspection
security find-certificate -c "AceIoT Client" -p \
  ~/Library/Keychains/login.keychain-db | \
  openssl x509 -noout -text
```

### Linux Requirements

#### Chrome/Chromium

Uses NSS database:
```bash
# Location
~/.pki/nssdb/

# Import P12
pk12util -i client.p12 -d sql:$HOME/.pki/nssdb -W p12password

# List certificates
certutil -L -d sql:$HOME/.pki/nssdb
```

#### Firefox

Uses own NSS database:
```bash
# Location
~/.mozilla/firefox/*.default-release/

# Import via GUI: Preferences → Privacy & Security → Certificates → View Certificates
```

### Windows Requirements

#### Certificate Store Locations

- **Current User** (`Cert:\CurrentUser\My`) - Recommended
- **Local Machine** (`Cert:\LocalMachine\My`) - Requires admin

#### Import via GUI

1. Double-click `.p12` file
2. Certificate Import Wizard opens
3. Enter P12 password
4. Select "Current User" store
5. Complete wizard

---

## API Reference

### Certificate Issuance

**POST** `/certificates/issue`

```json
{
  "common_name": "user@example.com",
  "organization": "AceIoT",
  "server_id": "config-server-01",
  "email": "user@example.com",
  "validity_hours": 1,
  "san_dns_names": ["localhost", "service.local"],
  "san_ip_addresses": ["127.0.0.1", "192.168.1.100"]
}
```

**Headers:**
- `X-API-Key: super-secret-key-change-in-production`
- `Content-Type: application/json`

**Response:**
```json
{
  "message": "Client certificate issued successfully",
  "certificate": {
    "serial_number": "123456789...",
    "common_name": "user@example.com",
    "issuer": "CN=config-server-01 Intermediate CA",
    "valid_from": "2025-11-08T17:00:00Z",
    "expires": "2025-11-08T18:00:00Z",
    "fingerprint": "SHA256:ABC123..."
  },
  "server_id": "config-server-01",
  "download": {
    "pem": "/certificates/12345/pem",
    "key": "/certificates/12345/key",
    "p12": "/certificates/12345/p12",
    "bundle": "/certificates/12345/bundle"
  }
}
```

### Download Formats

| Format | Endpoint | Use Case | Contains |
|--------|----------|----------|----------|
| **PEM** | `/certificates/{id}/pem` | curl, Python, most tools | Certificate only |
| **Key** | `/certificates/{id}/key` | With PEM for authentication | Private key only |
| **CA Chain** | `/certificates/{id}/ca-chain` | Trust verification | Intermediate + Root CA |
| **Bundle** | `/certificates/{id}/bundle` | All-in-one PEM | Cert + Key + CA Chain |
| **PKCS#12** | `/certificates/{id}/p12` | Browsers (Chrome, Safari) | Cert + Key + CA Chain |
| **DER** | `/certificates/{id}/der` | Binary format, Java | Certificate only |

---

## Troubleshooting

### Browser Issues

#### "No certificates available" in Chrome

**Symptoms:** Chrome doesn't show certificate selection dialog

**Causes:**
1. Certificate not in Login Keychain (macOS)
2. No private key association
3. Certificate expired
4. Chrome not restarted

**Solutions:**
```bash
# Verify identity exists
security find-identity -v ~/Library/Keychains/login.keychain-db | grep -i aceiot

# Should show: 1) ABC123... "AceIoT Client Certificate"

# If not shown:
./scripts/macos-cert-import.sh cleanup
./scripts/macos-cert-import.sh import ~/Downloads/client-*.p12

# Restart Chrome COMPLETELY
osascript -e 'quit app "Google Chrome"'
open -a "Google Chrome"
```

#### "Your connection is not private" (ERR_CERT_INVALID)

**Symptoms:** Browser shows security error for server

**Causes:**
1. Server certificate has no SANs
2. SANs don't match accessed hostname/IP
3. Root CA not trusted

**Solutions:**
```bash
# Check server certificate has SANs
openssl s_client -connect localhost:8501 -showcerts 2>/dev/null | \
  openssl x509 -noout -text | grep -A 10 "Subject Alternative Name"

# Should show:
# X509v3 Subject Alternative Name:
#     DNS:localhost, DNS:config-service, IP Address:127.0.0.1

# If missing SANs, regenerate server cert:
./scripts/generate-server-certs.sh

# Trust Root CA (macOS):
./scripts/macos-cert-import.sh trust
```

### Import Issues

#### "MAC verification failed" (macOS)

**Symptoms:**
```
security: SecKeychainItemImport: MAC verification failed during PKCS12 import (wrong password?)
```

**Cause:** Entered wrong P12 password

**Solution:**
1. Get correct password from download page (http://localhost:8000/ui/download)
2. Copy the 12-character password shown
3. Retry import with correct password
4. If password lost, issue new certificate

#### "Certificate already exists in keychain"

**Solution:**
```bash
# Remove old certificate first
./scripts/macos-cert-import.sh cleanup

# Then import new one
./scripts/macos-cert-import.sh import ~/Downloads/client-*.p12
```

### Certificate Expiration

**Symptoms:** Certificate was working, now shows errors

**Cause:** Short-lived certificates (1-hour TTL) expired

**Solution:**
```bash
# Check expiration
security find-certificate -c "AceIoT Client" -p \
  ~/Library/Keychains/login.keychain-db | \
  openssl x509 -noout -dates

# Issue new certificate
# Visit: http://localhost:8000/ui/download
```

---

## Security Considerations

### Production Deployment

**⚠️ This is designed for LOCAL TESTING. For production:**

1. **Change API Key:**
   ```bash
   # In .env
   API_KEY=<strong-random-key-here>
   ```

2. **Use HSM for Root CA:**
   - Store Root CA private key in Hardware Security Module
   - Or use external CA service (Let's Encrypt, AWS ACM, etc.)

3. **Implement Certificate Revocation:**
   - Add CRL (Certificate Revocation List) endpoint
   - Or implement OCSP (Online Certificate Status Protocol)

4. **Audit Logging:**
   - Log all certificate issuance events
   - Track certificate usage
   - Monitor for anomalies

5. **Rate Limiting:**
   - Limit certificate issuance per client
   - Prevent abuse

6. **Longer Server Certificate Validity:**
   - 1-hour TTL is impractical for servers
   - Use 1-year for dev, shorter for production with rotation

### Key Rotation

**Root CA:**
- Rotate every 5-10 years
- Gradual migration with dual-root support

**Intermediate CA:**
- Rotate every 1-5 years
- Can be done transparently to clients

**Client Certificates:**
- Short-lived (hours to days)
- Automatic rotation via UI/API

---

## Summary

### Critical Requirements Checklist

For successful mTLS deployment:

- ✅ Server certificates MUST have Subject Alternative Names (SANs)
- ✅ Certificates MUST have correct Extended Key Usage (EKU)
- ✅ P12 files MUST be password-protected for macOS
- ✅ macOS imports MUST use `-A` flag for Chrome access
- ✅ Certificates MUST be in Login Keychain (macOS)
- ✅ P12 MUST include complete CA chain
- ✅ Clients MUST have private key associated (identity)
- ✅ Chrome MUST be restarted completely after import

### Quick Start

```bash
# 1. Start services
podman-compose up -d

# 2. Generate server certificates
./scripts/generate-server-certs.sh

# 3. Issue client certificate
# Visit: http://localhost:8000/ui/download
# Copy the P12 password shown

# 4. Import client certificate (macOS)
./scripts/macos-cert-import.sh full-setup ~/Downloads/client-*.p12
# Enter P12 password when prompted
# Enter Mac login password when prompted

# 5. Restart Chrome
osascript -e 'quit app "Google Chrome"'
open -a "Google Chrome"

# 6. Test
open https://localhost:8501
# Select certificate when prompted
```

---

**Documentation Version:** 2.0.0
**Tested Platforms:** macOS 14.5, Chrome 120
**Contributors:** Claude Code, acedrew
