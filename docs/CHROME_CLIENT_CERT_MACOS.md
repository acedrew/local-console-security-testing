# Chrome Client Certificate on macOS - Complete Guide

## The Issue

Chrome on macOS shows the certificate in "Trusted Certificates" but not as a client certificate for authentication.

## Why This Happens

macOS Keychain has different certificate categories:
- **Certificates** - Shows all certificates (including CAs)
- **My Certificates** - Shows YOUR personal certificates with private keys
- **Keys** - Shows private keys

For Chrome to use a certificate for client authentication, it must:
1. ✅ Be in the **Login** keychain (not System)
2. ✅ Have an associated **private key**
3. ✅ Be marked as **always accessible** (or accessible by Chrome)
4. ✅ Have **Extended Key Usage: Client Authentication**

## ✅ Correct Import Process

### Step 1: Download P12 from PKI Service

Visit: **http://localhost:8000/ui/download**

Download the **.p12** file (e.g., `client-123456.p12`)

### Step 2: Import with Correct Flags

**IMPORTANT**: Use these exact flags:

```bash
security import ~/Downloads/client-*.p12 \
  -k ~/Library/Keychains/login.keychain-db \
  -T /Applications/Google\ Chrome.app \
  -T /Applications/Safari.app \
  -A
```

**What each flag does:**
- `-k ~/Library/Keychains/login.keychain-db` - Import to **Login** keychain (required for Chrome)
- `-T /Applications/Google\ Chrome.app` - Allow Chrome to access without prompt
- `-T /Applications/Safari.app` - Allow Safari to access without prompt
- `-A` - Mark private key as always accessible (no ACL restrictions)

**Note**: When prompted for password, just press **Enter** (P12 has no password).

### Step 3: Verify Import

```bash
# Check if certificate shows up in "My Certificates"
security find-identity -v ~/Library/Keychains/login.keychain-db | grep -i aceiot
```

You should see output like:
```
1) A1B2C3D4... "AceIoT Client Certificate" (CSSMERR_TP_NOT_TRUSTED)
```

The `CSSMERR_TP_NOT_TRUSTED` is OK - it just means the cert is for client auth, not server.

### Step 4: Verify in Keychain Access App

1. Open **Keychain Access** app
2. Select "**login**" keychain (left sidebar)
3. Select "**My Certificates**" category (left sidebar)
4. Look for your certificate - it should have a **key icon** next to it

If you see it in "**My Certificates**" with a key icon, it's correctly imported!

### Step 5: Restart Chrome COMPLETELY

**Critical**: Chrome only loads certificates on startup.

```bash
# Quit Chrome
osascript -e 'quit app "Google Chrome"'

# Wait a moment
sleep 2

# Reopen Chrome
open -a "Google Chrome"
```

Or manually: Press **Cmd+Q** in Chrome (don't just close the window!)

### Step 6: Test

Visit: **https://localhost:8501**

Chrome should now:
1. ✅ Accept the server certificate (because Root CA is trusted)
2. ✅ Prompt you to select a client certificate
3. ✅ Show your certificate in the selection dialog

## 🔍 Troubleshooting

### Certificate Shows in "Certificates" but Not "My Certificates"

**Problem**: The private key wasn't imported or associated properly.

**Solution**: Delete and re-import with the `-A` flag:

```bash
# Delete old certificate
security delete-certificate -c "your-cert-common-name" ~/Library/Keychains/login.keychain-db

# Re-import with -A flag
security import ~/Downloads/client-*.p12 \
  -k ~/Library/Keychains/login.keychain-db \
  -T /Applications/Google\ Chrome.app \
  -A
```

### Chrome Still Not Showing Certificate

**Checklist**:

1. ✅ Certificate is in **Login** keychain (not System)
   ```bash
   security find-identity -v ~/Library/Keychains/login.keychain-db | grep AceIoT
   ```

2. ✅ Has a private key (check in Keychain Access → My Certificates → should have key icon)

3. ✅ Chrome was **fully restarted** (Cmd+Q, not just close window)

4. ✅ Certificate has not expired (1-hour TTL by default)
   ```bash
   # Check expiration
   security find-certificate -c "your-cert" -p ~/Library/Keychains/login.keychain-db | \
     openssl x509 -noout -dates
   ```

### "This certificate is marked as not trusted"

**This is NORMAL** for client certificates! The `CSSMERR_TP_NOT_TRUSTED` message just means:
- It's a client certificate (not a CA certificate)
- It's for authentication, not for verifying servers

This does NOT prevent Chrome from using it.

### Certificate Expired

Client certificates have a **1-hour TTL** by default. Just issue a new one:

```bash
# Visit PKI UI and download new P12
open http://localhost:8000/ui/download

# Import new certificate (will replace old one)
security import ~/Downloads/client-*.p12 \
  -k ~/Library/Keychains/login.keychain-db \
  -T /Applications/Google\ Chrome.app \
  -A

# Restart Chrome
osascript -e 'quit app "Google Chrome"'
open -a "Google Chrome"
```

## 📱 Alternative: Using Keychain Access GUI

If you prefer a graphical interface:

1. **Open Keychain Access** app
2. Select "**login**" keychain (left sidebar)
3. Go to **File → Import Items...**
4. Select your `.p12` file
5. When prompted:
   - Enter password (press Enter for none)
   - Choose "**login**" keychain
6. After import, find the certificate
7. **Double-click** the certificate
8. Expand "**Trust**" section
9. For "Code Signing" set to "**Always Trust**" (optional, helps with access)
10. Close (will prompt for password)
11. **Restart Chrome**

## 🎯 Quick Reference

```bash
# Download P12 from UI
open http://localhost:8000/ui/download

# Import to Login keychain with proper access
security import ~/Downloads/client-*.p12 \
  -k ~/Library/Keychains/login.keychain-db \
  -T /Applications/Google\ Chrome.app \
  -A

# Verify it's there
security find-identity -v ~/Library/Keychains/login.keychain-db | grep AceIoT

# Restart Chrome
osascript -e 'quit app "Google Chrome"' && sleep 2 && open -a "Google Chrome"

# Test
open https://localhost:8501
```

## ✅ Success Indicators

When everything is working:

1. **In Keychain Access**:
   - Certificate appears in "My Certificates"
   - Has a key icon next to it
   - Shows in Login keychain

2. **In Terminal**:
   ```bash
   security find-identity -v ~/Library/Keychains/login.keychain-db | grep AceIoT
   # Shows: 1) ABC123... "certificate-name"
   ```

3. **In Chrome**:
   - Visiting https://localhost:8501 shows certificate selection dialog
   - Your certificate appears in the list
   - After selecting, page loads successfully

---

**Key Takeaway**: Always use the `-A` flag when importing P12 files for Chrome on macOS!

**Last Updated**: 2025-11-08
