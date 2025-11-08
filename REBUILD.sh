#!/bin/bash
# Quick rebuild script for Podman Compose

set -e

echo "🛑 Stopping existing containers..."
podman-compose down

echo "🗑️  Removing old images..."
podman rmi -f localhost/local-console-security-testing_pki-service:latest 2>/dev/null || true
podman rmi -f localhost/local-console-security-testing_config-service:latest 2>/dev/null || true

echo "🔨 Rebuilding containers..."
podman-compose build --no-cache

echo "🚀 Starting services..."
podman-compose up -d

echo ""
echo "✅ Rebuild complete!"
echo ""
echo "📊 Container status:"
podman-compose ps

echo ""
echo "📝 View logs with:"
echo "  podman-compose logs -f"
echo ""
echo "🌐 Access services at:"
echo "  PKI Service: http://localhost:8000"
echo "  API Docs:    http://localhost:8000/docs"
echo "  Config UI:   http://localhost:8501"
