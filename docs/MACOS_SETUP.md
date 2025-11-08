# 🍎 macOS Certificate Setup Guide

Complete guide for using mTLS client certificates on macOS with Chrome, Safari, and curl.

## 🚨 Important: Chrome on macOS Uses Login Keychain

Chrome on macOS **only** checks the **Login Keychain**, not the System Keychain. This is why certificates might not show up even after import.

## ✅ Automated Setup (Recommended)

### Quick Start

```bash
# 1. Download P12 file from PKI service
# Visit: http://localhost:8000/ui/download

# 2. Run the automated setup script
./scripts/macos-cert-import.sh full-setup ~/Downloads/client-*.p12

# 3. Restart Chrome completely (Cmd+Q, then reopen)

# 4. Visit: https://localhost:8501
```

That's it! Chrome should now prompt you to select your certificate.

## 📋 Manual Setup (Step by Step)

### Step 1: Download Certificates

1. Visit: **http://localhost:8000/ui/download**
2. Fill in the form:
   - Device Name: `my-macbook`
   - Server ID: `config-server-01`
   - Email (optional): `you@example.com`
3. Click "Issue Certificate"
4. Download the **P12** file (e.g., `client-123456.p12`)

### Step 2: Trust the Root CA

```bash
# Extract and trust root CA
./scripts/macos-cert-import.sh trust
```

**Or manually:**

```bash
# Download root CA
curl -s http://localhost:8000/ca/intermediate/config-server-01 | \
  jq -r '.ca_chain' | \
  awk '/-----BEGIN CERTIFICATE-----/{flag=1; cert=""}
       flag{cert=cert $0 "\n"}
       /-----END CERTIFICATE-----/{if(flag){last=cert}; flag=0}
       END{print last}' > ~/Downloads/aceiot-root-ca.pem

# Import and trust
sudo security add-trusted-cert -d -r trustRoot \
  -k ~/Library/Keychains/login.keychain-db \
  ~/Downloads/aceiot-root-ca.pem
```

### Step 3: Import Client Certificate

```bash
# Import P12 file to Login Keychain
security import ~/Downloads/client-*.p12 \
  -k ~/Library/Keychains/login.keychain-db \
  -T /Applications/Google\ Chrome.app \
  -T /Applications/Safari.app \
  -T /usr/bin/curl
```

**Note**: If prompted for a password, just press **Enter** (no password is set).

### Step 4: Verify Import

Open **Keychain Access** app:
1. Select "login" keychain (left sidebar)
2. Select "Certificates" category
3. Look for certificates with "AceIoT" in the name:
   - **AceIoT Root CA** (green checkmark = trusted)
   - **Your client certificate** (e.g., "my-macbook")

### Step 5: Restart Chrome

**IMPORTANT**: Chrome must be fully restarted:

```bash
# Quit Chrome completely
osascript -e 'quit app "Google Chrome"'

# Wait a moment
sleep 2

# Reopen Chrome
open -a "Google Chrome"
```

Or use **Cmd+Q** to quit, then reopen.

## 🔍 Troubleshooting

### Chrome Not Showing Certificate Selection

**Problem**: When visiting https://localhost:8501, Chrome doesn't prompt for certificate.

**Solutions**:

1. **Restart Chrome completely** (Cmd+Q, not just close window)
   ```bash
   osascript -e 'quit app "Google Chrome"'
   open -a "Google Chrome"
   ```

2. **Verify certificate is in Login Keychain** (NOT System Keychain)
   ```bash
   ./scripts/macos-cert-import.sh verify
   ```

3. **Check Keychain Access app**:
   - Open Keychain Access
   - Select "login" keychain
   - Select "My Certificates" category
   - Should see your client certificate with a key icon

4. **Re-import to Login Keychain**:
   ```bash
   ./scripts/macos-cert-import.sh cleanup
   ./scripts/macos-cert-import.sh full-setup ~/Downloads/client-*.p12
   ```

### Certificate Shows Red X in Keychain Access

**Problem**: Root CA shows "This certificate is marked as not trusted"

**Solution**: Trust the root CA:

```bash
# Via script
./scripts/macos-cert-import.sh trust

# Or manually in Keychain Access:
# 1. Double-click the "AceIoT Root CA"
# 2. Expand "Trust" section
# 3. Set "Secure Sockets Layer (SSL)" to "Always Trust"
# 4. Close (will prompt for password)
```

### "This Connection is Not Private" Error

**Problem**: Browser shows NET::ERR_CERT_AUTHORITY_INVALID

**Causes**:
1. Root CA not trusted
2. Wrong keychain (must be Login, not System)
3. Certificate expired (1-hour TTL)

**Solution**:

```bash
# Check certificate is valid
openssl x509 -in ~/Downloads/client-*.pem -noout -dates

# If expired, issue a new one at:
# http://localhost:8000/ui/download
```

### Safari Works But Chrome Doesn't

**Problem**: Safari shows certificate selection, Chrome doesn't.

**Solution**: This usually means certificate is in System Keychain instead of Login Keychain.

```bash
# Re-import to Login Keychain
./scripts/macos-cert-import.sh cleanup
./scripts/macos-cert-import.sh import ~/Downloads/client-*.p12
```

## 🌐 Browser-Specific Instructions

### Chrome

1. Certificate must be in **Login Keychain**
2. Root CA must be **trusted for SSL**
3. **Full restart required** (Cmd+Q, not just close window)
4. Visit: https://localhost:8501
5. Chrome will prompt for certificate selection

### Safari

1. Works with both Login and System Keychain
2. May need to enable client certificates in preferences
3. Safari → Preferences → Advanced → "Show Develop menu"
4. Develop → Show Web Inspector → Security tab

### Firefox

Firefox uses its own certificate store (doesn't use macOS Keychain):

1. Open Firefox Preferences
2. Privacy & Security → Certificates → "View Certificates"
3. "Your Certificates" tab → "Import"
4. Select the P12 file
5. "Authorities" tab → "Import"
6. Select the Root CA PEM file

## 🔧 Command-Line Testing

### curl

```bash
# Test with separate files
curl --cert ~/Downloads/client-cert-*.pem \
     --key ~/Downloads/client-key-*.pem \
     --cacert ~/Downloads/ca-chain-*.pem \
     https://localhost:8501/api/config

# Test with bundle
curl --cert ~/Downloads/client-bundle-*.pem \
     --cacert ~/Downloads/ca-chain-*.pem \
     https://localhost:8501/api/config
```

### openssl s_client

```bash
# Test TLS connection
openssl s_client -connect localhost:8501 \
  -cert ~/Downloads/client-cert-*.pem \
  -key ~/Downloads/client-key-*.pem \
  -CAfile ~/Downloads/ca-chain-*.pem
```

## 📱 Additional Tools

### List All Certificates

```bash
# List login keychain certificates
security find-certificate -a ~/Library/Keychains/login.keychain-db | grep "labl"

# List only AceIoT certificates
./scripts/macos-cert-import.sh verify
```

### Export Certificate from Keychain

```bash
# Export as PEM
security find-certificate -c "my-macbook" -p ~/Library/Keychains/login.keychain-db > exported-cert.pem
```

### Delete Certificate

```bash
# Via script
./scripts/macos-cert-import.sh cleanup

# Or manually in Keychain Access:
# Right-click certificate → Delete "certificate-name"
```

## 🎯 Helper Script Reference

```bash
# Full automated setup
./scripts/macos-cert-import.sh full-setup <p12-file>

# Trust root CA only
./scripts/macos-cert-import.sh trust

# Import P12 only
./scripts/macos-cert-import.sh import <p12-file>

# Verify setup
./scripts/macos-cert-import.sh verify

# Clean up all AceIoT certificates
./scripts/macos-cert-import.sh cleanup

# Show help
./scripts/macos-cert-import.sh help
```

## 💡 Pro Tips

1. **Use the automated script** - It handles all the quirks of macOS keychain
2. **Always use Login Keychain for Chrome** - System Keychain won't work
3. **Restart Chrome completely** - Window close isn't enough
4. **Certificates expire in 1 hour** - Just issue a new one when needed
5. **Check Keychain Access app** - Visual confirmation helps debugging

## 📚 Related Documentation

- [Quick Start Guide](./QUICK_START.md)
- [Testing Guide](./MTLS_TESTING_GUIDE.md)
- [Certificate Download Guide](./CERTIFICATE_DOWNLOAD_GUIDE.md)

---

**Tested on**: macOS Sonoma 14.x, Chrome 120+, Safari 17+
**Last Updated**: 2025-11-08
