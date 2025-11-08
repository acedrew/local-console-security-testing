#!/bin/bash
# macOS Certificate Import Helper
# Properly imports PKI certificates for use with Chrome and other applications

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "🍎 macOS Certificate Import Helper"
echo "==================================="
echo ""

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "❌ This script is for macOS only!"
    exit 1
fi

# Function to extract Root CA from PKI service
extract_root_ca() {
    echo "📥 Downloading Root CA from PKI service..."

    # Get intermediate CA which includes full chain
    CHAIN_DATA=$(curl -s http://localhost:8000/ca/intermediate/config-server-01 | jq -r '.ca_chain')

    # Extract just the root CA (last certificate in chain)
    echo "$CHAIN_DATA" | awk '/-----BEGIN CERTIFICATE-----/{flag=1; cert=""} flag{cert=cert $0 "\n"} /-----END CERTIFICATE-----/{if(flag){last=cert}; flag=0} END{print last}' > /tmp/aceiot-root-ca.pem

    if [ ! -s /tmp/aceiot-root-ca.pem ]; then
        echo "❌ Failed to extract root CA"
        return 1
    fi

    echo "✅ Root CA extracted to /tmp/aceiot-root-ca.pem"

    # Display CA info
    echo ""
    echo "Root CA Information:"
    openssl x509 -in /tmp/aceiot-root-ca.pem -noout -subject -issuer -dates
    echo ""
}

# Function to trust root CA
trust_root_ca() {
    echo "🔐 Installing Root CA into Login Keychain..."

    # Import into login keychain
    security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db /tmp/aceiot-root-ca.pem 2>/dev/null || \
    security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain /tmp/aceiot-root-ca.pem

    echo "✅ Root CA installed and trusted"
    echo ""
}

# Function to import P12 file
import_p12() {
    local p12_file="$1"

    if [ -z "$p12_file" ]; then
        echo "Usage: $0 import <path-to-p12-file>"
        return 1
    fi

    if [ ! -f "$p12_file" ]; then
        echo "❌ File not found: $p12_file"
        return 1
    fi

    echo "📦 Importing P12 certificate: $p12_file"
    echo ""
    echo "⚠️  You will see TWO password prompts:"
    echo "   1. 'Enter password for PKCS12' → Enter the P12 password from the download page"
    echo "   2. 'Enter password for keychain' → Enter your Mac login password"
    echo ""
    echo "💡 Get the P12 password from: http://localhost:8000/ui/download"
    echo "   (It's displayed prominently on the certificate download page)"
    echo ""

    # Import into login keychain with -A flag (critical for Chrome!)
    # -A makes the private key always accessible without ACL restrictions
    # This is required for Chrome to see it as a client certificate
    echo "Importing..."
    security import "$p12_file" \
        -k ~/Library/Keychains/login.keychain-db \
        -T /Applications/Google\ Chrome.app \
        -T /Applications/Safari.app \
        -T /usr/bin/curl \
        -A 2>&1 | grep -v "password" || \
    security import "$p12_file" \
        -k ~/Library/Keychains/login.keychain \
        -T /Applications/Google\ Chrome.app \
        -T /Applications/Safari.app \
        -T /usr/bin/curl \
        -A

    if [ $? -eq 0 ]; then
        echo ""
        echo "✅ P12 certificate imported to Login Keychain with full access"
        echo "   The -A flag ensures Chrome can use the private key"
        echo ""
    else
        echo ""
        echo "❌ Import failed. Try again or import manually via Keychain Access app"
        echo ""
        return 1
    fi
}

# Function to verify setup
verify_setup() {
    echo "🔍 Verifying Certificate Setup..."
    echo ""

    # Check if root CA is in keychain
    if security find-certificate -c "AceIoT Root CA" ~/Library/Keychains/login.keychain-db >/dev/null 2>&1 || \
       security find-certificate -c "AceIoT Root CA" ~/Library/Keychains/login.keychain >/dev/null 2>&1; then
        echo "✅ Root CA found in Login Keychain"
    else
        echo "❌ Root CA not found in Login Keychain"
        echo "   Run: $0 trust"
    fi

    # Check for client certificates with private keys (identities)
    echo ""
    echo "🔑 Client Certificates with Private Keys (usable by Chrome):"
    if security find-identity -v ~/Library/Keychains/login.keychain-db 2>/dev/null | grep -i "aceiot\|client" || \
       security find-identity -v ~/Library/Keychains/login.keychain 2>/dev/null | grep -i "aceiot\|client"; then
        echo ""
        echo "✅ Client certificate(s) with private keys found!"
    else
        echo "   (none found)"
        echo ""
        echo "⚠️  No client certificates with private keys"
        echo "   This is why Chrome isn't showing them!"
        echo ""
        echo "   Download P12 from: http://localhost:8000/ui/download"
        echo "   Then run: $0 import <path-to-p12>"
    fi

    echo ""
    echo "📋 All AceIoT Certificates in Login Keychain:"
    security find-certificate -a -c "AceIoT" ~/Library/Keychains/login.keychain-db 2>/dev/null | grep "labl" || \
    security find-certificate -a -c "AceIoT" ~/Library/Keychains/login.keychain 2>/dev/null | grep "labl" || \
    echo "   (none found)"
    echo ""
}

# Function to show help
show_help() {
    cat <<EOF
Usage: $0 <command> [arguments]

Commands:
    trust               Download and trust the AceIoT Root CA
    import <p12-file>   Import a client certificate P12 file
    verify              Verify certificate setup
    full-setup <p12>    Complete setup: trust CA + import P12
    cleanup             Remove all AceIoT certificates from keychain
    help                Show this help message

Examples:
    # Trust the root CA
    $0 trust

    # Import a client certificate
    $0 import ~/Downloads/client-123456.p12

    # Complete setup in one step
    $0 full-setup ~/Downloads/client-123456.p12

    # Verify everything is set up correctly
    $0 verify

Chrome Usage:
    1. Run: $0 full-setup <your-p12-file>
    2. Restart Chrome completely (Cmd+Q, then reopen)
    3. Visit: https://localhost:8501
    4. Chrome should prompt you to select your certificate

Troubleshooting:
    - Chrome not showing certificate? Restart Chrome completely (Cmd+Q)
    - Still not working? Try: $0 cleanup, then $0 full-setup <p12>
    - Check Keychain Access app: Look for "AceIoT" certificates in Login keychain

EOF
}

# Function for full setup
full_setup() {
    local p12_file="$1"

    echo "🚀 Running Full Certificate Setup"
    echo "================================="
    echo ""

    # Trust root CA
    extract_root_ca
    trust_root_ca

    # Import P12 if provided
    if [ -n "$p12_file" ]; then
        import_p12 "$p12_file"
    fi

    # Verify
    verify_setup

    echo "================================="
    echo "✅ Setup Complete!"
    echo ""
    echo "📌 Next Steps:"
    echo "   1. Restart Chrome completely (Cmd+Q, then reopen)"
    echo "   2. Visit: https://localhost:8501"
    echo "   3. Chrome will prompt you to select your certificate"
    echo ""
    echo "💡 To view certificates: Open Keychain Access app → Login → Certificates"
    echo ""
}

# Function to cleanup
cleanup() {
    echo "🧹 Removing AceIoT Certificates from Login Keychain..."
    echo ""

    # Find and delete all AceIoT certificates
    security find-certificate -a -c "AceIoT" -Z ~/Library/Keychains/login.keychain-db 2>/dev/null | \
        grep "SHA-1" | awk '{print $NF}' | \
        xargs -I {} security delete-certificate -Z {} ~/Library/Keychains/login.keychain-db 2>/dev/null || true

    security find-certificate -a -c "AceIoT" -Z ~/Library/Keychains/login.keychain 2>/dev/null | \
        grep "SHA-1" | awk '{print $NF}' | \
        xargs -I {} security delete-certificate -Z {} ~/Library/Keychains/login.keychain 2>/dev/null || true

    echo "✅ Cleanup complete"
    echo ""
}

# Main script logic
case "${1:-help}" in
    trust)
        extract_root_ca
        trust_root_ca
        ;;
    import)
        import_p12 "$2"
        ;;
    verify)
        verify_setup
        ;;
    full-setup)
        full_setup "$2"
        ;;
    cleanup)
        cleanup
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "❌ Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
