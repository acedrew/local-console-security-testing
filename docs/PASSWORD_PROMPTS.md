# Password Prompts - Quick Reference

When importing P12 certificates on macOS, you'll see **TWO** password prompts. Here's what each one means:

## Prompt 1: P12 File Password

**What you'll see:**
```
Enter Import Password:
```
or
```
Enter password for PKCS12 import (or empty for no password):
```

**What to do:**
Enter the **P12 password** displayed on the download page (a 12-character random password)

**Why:**
macOS requires P12 files to be password-protected for import. The PKI service generates a unique random password for each certificate and displays it on the download page.

---

## Prompt 2: Keychain Password

**What you'll see:**
```
security wants to modify the keychain "login.keychain-db"
Enter password to allow this:
```
or
```
Enter password for keychain "/Users/yourname/Library/Keychains/login.keychain-db":
```

**What to do:**
Enter your **macOS login password** (the password you use to log into your Mac)

**Why:**
The `-A` flag we use makes the private key always accessible, which requires admin authorization to modify the keychain.

---

## Complete Import Sequence

```bash
./scripts/macos-cert-import.sh import ~/Downloads/client-123456.p12
```

**Step-by-step:**

1. Script starts importing...

2. **First prompt appears:**
   ```
   Enter Import Password:
   ```
   → Enter the **P12 password** from the download page (e.g., `aB3dE5fG7hI9`)

3. **Second prompt appears:**
   ```
   security wants to modify the keychain "login.keychain-db"
   Enter password to allow this:
   ```
   → Type your **Mac login password** and press Enter

4. Done! Certificate imported.

---

## P12 Password Generation

The PKI service automatically generates a secure 12-character random password for each P12 file. This is required because:

1. macOS `security` command requires P12 files to be encrypted
2. Unencrypted P12 files fail with "MAC verification failed" error
3. Each certificate gets a unique password displayed on the download page

**Where to find your P12 password:**
1. Visit http://localhost:8000/ui/download
2. Issue certificate
3. The password is prominently displayed on the download success page
4. Click "Copy" to copy it to your clipboard

---

## Troubleshooting

### "Import failed" Error

If you see an error like:
```
security: SecKeychainItemImport: The specified item already exists in the keychain.
```

**Solution:** Delete the old certificate first:
```bash
./scripts/macos-cert-import.sh cleanup
./scripts/macos-cert-import.sh import ~/Downloads/client-*.p12
```

### Wrong Password Entered

If you enter the wrong P12 password:

**Just try again:**
```bash
./scripts/macos-cert-import.sh import ~/Downloads/client-*.p12
```

Make sure to copy the correct password from the download page. If you've lost the password, you'll need to issue a new certificate.

---

## Manual Import (Without -A Flag)

If you don't want to use `-A` flag and avoid the keychain modification password prompt:

```bash
security import ~/Downloads/client-*.p12 \
  -k ~/Library/Keychains/login.keychain-db
```

**Downsides:**
- You'll get prompted each time Chrome tries to use the certificate
- Less convenient for repeated use

**Upsides:**
- Only asks for P12 password (from download page)
- No keychain modification password needed

---

## Summary

| Prompt | What to Enter | Why |
|--------|---------------|-----|
| "Enter Import Password" | **P12 password from download page** | macOS requires encrypted P12 files |
| "Enter password for keychain" | Your **Mac login password** | Needed for `-A` flag (full access) |

**Key Point**: The first password is for the **P12 file** (from download page), the second is for **your Mac** (required for keychain modification).
