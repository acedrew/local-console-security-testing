# 🍎 Chrome on macOS - Client Certificate Solution

## The Problem

After importing the P12 file and trusting the CA on macOS, Chrome doesn't show the client certificate in the selection dialog when visiting the mTLS-protected site.

## Why This Happens

Chrome on macOS has specific requirements that differ from other platforms:

1. **Login Keychain Only**: Chrome **only** checks the `Login` keychain, not the `System` keychain
2. **Full Restart Required**: Window close isn't enough - Chrome must be fully quit (Cmd+Q)
3. **Proper Import Permissions**: The P12 must be imported with explicit access rights for Chrome.app
4. **Root CA Trust**: The Root CA must be explicitly trusted for "Secure Sockets Layer (SSL)"

## ✅ Solution: Automated Helper Script

We've created a helper script that handles all the macOS-specific quirks:

```bash
./scripts/macos-cert-import.sh full-setup ~/Downloads/client-*.p12
```

This script will:
1. ✅ Download and install the Root CA
2. ✅ Mark it as trusted for SSL in the Login Keychain
3. ✅ Import your P12 with proper Chrome access rights
4. ✅ Verify everything is set up correctly

## 📋 Step-by-Step Instructions

### 1. Download Your Certificate

Visit: http://localhost:8000/ui/download

Fill in:
- Device Name: `my-macbook`
- Server ID: `config-server-01`
- Click "Issue Certificate"
- Download the **P12** file (e.g., `client-123456.p12`)

### 2. Run the Setup Script

```bash
./scripts/macos-cert-import.sh full-setup ~/Downloads/client-*.p12
```

**When prompted**:
- For password: Just press **Enter** (no password is set)
- For admin password: Enter your macOS password (needed to trust the CA)

### 3. Restart Chrome Completely

**This is critical!** Chrome must be fully quit, not just window closed:

```bash
# Quit Chrome
osascript -e 'quit app "Google Chrome"'

# Wait a moment
sleep 2

# Reopen Chrome
open -a "Google Chrome"
```

**Or manually**: Press **Cmd+Q** in Chrome, wait a moment, then reopen.

### 4. Visit the Protected Site

```
https://localhost:8501
```

Chrome should now prompt you to select your client certificate!

## 🔍 Verification

Check that everything is set up correctly:

```bash
./scripts/macos-cert-import.sh verify
```

You should see:
- ✅ Root CA found in Login Keychain
- ✅ Client certificate(s) found in Login Keychain

## 🛠️ Troubleshooting

### Still Not Working?

Try the cleanup and re-import:

```bash
# Remove all AceIoT certificates
./scripts/macos-cert-import.sh cleanup

# Re-download P12 from http://localhost:8000/ui/download

# Run full setup again
./scripts/macos-cert-import.sh full-setup ~/Downloads/client-*.p12

# Restart Chrome completely
osascript -e 'quit app "Google Chrome"'
open -a "Google Chrome"
```

### Check Keychain Access App

1. Open **Keychain Access** app
2. Select "**login**" keychain (left sidebar)
3. Select "**My Certificates**" category
4. Look for your certificate (should have a key icon next to it)
5. Select "**Certificates**" category
6. Find "**AceIoT Root CA**" - should have a green checkmark

### Safari Works But Chrome Doesn't?

This usually means the certificate is in the **System** keychain instead of **Login**.

**Solution**:
```bash
./scripts/macos-cert-import.sh cleanup
./scripts/macos-cert-import.sh import ~/Downloads/client-*.p12
```

Make sure it imports to the **Login** keychain specifically.

## 📚 Additional Resources

- **Complete macOS Guide**: [MACOS_SETUP.md](./MACOS_SETUP.md)
- **Quick Start**: [QUICK_START.md](./QUICK_START.md)
- **Testing Guide**: [MTLS_TESTING_GUIDE.md](./MTLS_TESTING_GUIDE.md)

## 🎯 Helper Script Commands

```bash
# Full automated setup
./scripts/macos-cert-import.sh full-setup <p12-file>

# Trust root CA only
./scripts/macos-cert-import.sh trust

# Import P12 only
./scripts/macos-cert-import.sh import <p12-file>

# Verify setup
./scripts/macos-cert-import.sh verify

# Clean up
./scripts/macos-cert-import.sh cleanup

# Show help
./scripts/macos-cert-import.sh help
```

## 💡 Key Takeaways

1. ✅ Use the **automated script** - it handles all macOS quirks
2. ✅ **Login Keychain** is required for Chrome (not System)
3. ✅ **Full Chrome restart** is mandatory (Cmd+Q)
4. ✅ Verify in **Keychain Access** app before testing
5. ✅ Certificates **expire in 1 hour** - just issue a new one when needed

---

**This solution has been tested on**:
- macOS Sonoma 14.x
- Google Chrome 120+
- Safari 17+

**Last Updated**: 2025-11-08
