#!/bin/bash
# ==============================================================================
# Setup script for Podman Compose environment
# ==============================================================================

set -e  # Exit on error

echo "🚀 Setting up PKI system for Podman Compose..."

# -----------------------------------------------------------------------------
# Check dependencies
# -----------------------------------------------------------------------------
echo "📋 Checking dependencies..."

if ! command -v podman &> /dev/null; then
    echo "❌ Error: podman is not installed"
    echo "   Install with: brew install podman (macOS) or your package manager"
    exit 1
fi

if ! command -v podman-compose &> /dev/null; then
    echo "⚠️  Warning: podman-compose is not installed"
    echo "   Install with: pip install podman-compose"
    echo "   Attempting to install..."
    pip install podman-compose
fi

echo "✅ Dependencies checked"

# -----------------------------------------------------------------------------
# Create directory structure
# -----------------------------------------------------------------------------
echo "📁 Creating directory structure..."

mkdir -p data/{pki,config,logs/{pki,config}}
mkdir -p data/pki/{ca/{root_ca,intermediate_cas},certificates}

echo "✅ Directories created"

# -----------------------------------------------------------------------------
# Set permissions
# -----------------------------------------------------------------------------
echo "🔒 Setting permissions..."

# Get current user UID/GID
CURRENT_UID=$(id -u)
CURRENT_GID=$(id -g)

# Ensure data directories are owned by current user
if [ -d "data" ]; then
    chown -R ${CURRENT_UID}:${CURRENT_GID} data/ 2>/dev/null || true
    chmod -R 755 data/
fi

echo "✅ Permissions set (UID: ${CURRENT_UID}, GID: ${CURRENT_GID})"

# -----------------------------------------------------------------------------
# Create .env file if it doesn't exist
# -----------------------------------------------------------------------------
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file..."

    cat > .env << EOF
# Auto-generated environment file
PKI_PORT=8000
CONFIG_PORT=8501
PKI_LOG_LEVEL=INFO
PKI_CERT_LIFETIME=3600
UID=${CURRENT_UID}
GID=${CURRENT_GID}
TZ=UTC
PYTHONUNBUFFERED=1
EOF

    echo "✅ .env file created"
else
    echo "✅ .env file already exists"
fi

# -----------------------------------------------------------------------------
# Initialize podman machine (macOS only)
# -----------------------------------------------------------------------------
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍎 Detected macOS - checking podman machine..."

    if ! podman machine list | grep -q "Currently running"; then
        echo "   Starting podman machine..."
        podman machine start 2>/dev/null || podman machine init && podman machine start
    fi

    echo "✅ Podman machine running"
fi

# -----------------------------------------------------------------------------
# Display usage instructions
# -----------------------------------------------------------------------------
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    🎉 Setup Complete!                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "📚 Quick Start Guide:"
echo ""
echo "1️⃣  Build the containers:"
echo "   podman-compose build"
echo ""
echo "2️⃣  Start the services:"
echo "   podman-compose up -d"
echo ""
echo "3️⃣  Check the logs:"
echo "   podman-compose logs -f pki-service"
echo "   podman-compose logs -f config-service"
echo ""
echo "4️⃣  Access the services:"
echo "   • PKI Service:    http://localhost:8000"
echo "   • API Docs:       http://localhost:8000/docs"
echo "   • Config UI:      http://localhost:8501"
echo ""
echo "5️⃣  Stop the services:"
echo "   podman-compose down"
echo ""
echo "📖 Additional commands:"
echo "   podman-compose ps              # Check service status"
echo "   podman-compose exec pki-service bash  # Shell into container"
echo "   podman-compose restart         # Restart all services"
echo ""
echo "🔧 Configuration:"
echo "   Edit .env file to customize settings"
echo ""
echo "📁 Data directories:"
echo "   ./data/pki/        - CA keys and certificates"
echo "   ./data/config/     - Configuration files"
echo "   ./data/logs/       - Service logs"
echo ""

# -----------------------------------------------------------------------------
# Optional: Start services automatically
# -----------------------------------------------------------------------------
read -p "❓ Would you like to start the services now? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🚀 Building and starting services..."
    podman-compose build
    podman-compose up -d

    echo ""
    echo "⏳ Waiting for services to be healthy..."
    sleep 5

    echo ""
    podman-compose ps

    echo ""
    echo "✅ Services are starting!"
    echo "   Check logs with: podman-compose logs -f"
fi

echo ""
echo "✨ All done! Happy developing!"
