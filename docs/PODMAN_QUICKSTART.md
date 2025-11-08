# 🐳 Podman Compose Quick Start Guide

This guide will help you spin up the PKI system using Podman Compose.

## 📋 Prerequisites

### Install Podman

**macOS:**
```bash
brew install podman
```

**Linux (Fedora/RHEL/CentOS):**
```bash
sudo dnf install podman
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install podman
```

### Install Podman Compose

```bash
pip install podman-compose
```

Or with pipx:
```bash
pipx install podman-compose
```

## 🚀 Quick Start (Automated)

The easiest way to get started:

```bash
# Run the setup script
./scripts/setup-podman.sh

# Follow the prompts
# It will:
# - Check dependencies
# - Create directories
# - Set permissions
# - Create .env file
# - Optionally start services
```

## 🛠️ Manual Setup

If you prefer to set things up manually:

### 1. Create Required Directories

```bash
mkdir -p data/{pki,config,logs/{pki,config}}
mkdir -p data/pki/{ca/{root_ca,intermediate_cas},certificates}
```

### 2. Set Permissions

```bash
# Ensure data directories are owned by your user
chown -R $UID:$GID data/
chmod -R 755 data/
```

### 3. Create Environment File

```bash
# Copy example to .env
cp .env.example .env

# Edit if needed
nano .env
```

### 4. Initialize Podman (macOS only)

```bash
# Create and start podman machine
podman machine init
podman machine start

# Verify it's running
podman machine list
```

### 5. Build and Start Services

```bash
# Build the container images
podman-compose build

# Start services in background
podman-compose up -d

# Or start with logs visible
podman-compose up
```

## 📊 Verify Services

### Check Status

```bash
# View running containers
podman-compose ps

# Expected output:
# NAME            IMAGE                           COMMAND                 STATUS
# pki-service     pki-service:latest              python -m src.pki...    Up
# config-service  config-service:latest           streamlit run...        Up
```

### View Logs

```bash
# Follow logs for all services
podman-compose logs -f

# Follow logs for specific service
podman-compose logs -f pki-service
podman-compose logs -f config-service
```

### Health Checks

```bash
# Check PKI service health
curl http://localhost:8000/health

# Check if Streamlit is running
curl http://localhost:8501/_stcore/health
```

## 🌐 Access Services

Once running, you can access:

| Service | URL | Description |
|---------|-----|-------------|
| **PKI Service** | http://localhost:8000 | REST API for certificate management |
| **API Docs** | http://localhost:8000/docs | Interactive API documentation (Swagger) |
| **Config Interface** | http://localhost:8501 | Streamlit configuration UI |

## 🧪 Test the PKI System

### 1. Access API Documentation

Open your browser to http://localhost:8000/docs

### 2. Get Root CA Info

```bash
curl http://localhost:8000/ca/root
```

### 3. Create an Intermediate CA

```bash
curl -X POST http://localhost:8000/ca/intermediate \
  -H "Content-Type: application/json" \
  -d '{
    "server_id": "test-server-001",
    "organization": "Test Org",
    "validity_days": 365
  }'
```

### 4. Issue a Client Certificate

```bash
curl -X POST http://localhost:8000/certificates/issue \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "test-client",
    "organization": "Test Org",
    "server_id": "test-server-001",
    "email": "test@example.com",
    "validity_hours": 1
  }'
```

### 5. View Configuration Interface

Open http://localhost:8501 in your browser to access the Streamlit UI.

## 🔧 Common Operations

### Restart Services

```bash
# Restart all services
podman-compose restart

# Restart specific service
podman-compose restart pki-service
```

### View Service Details

```bash
# Get detailed service info
podman-compose ps --format json

# Inspect specific container
podman inspect pki-service
```

### Execute Commands in Container

```bash
# Open shell in PKI service
podman-compose exec pki-service bash

# Run Python shell
podman-compose exec pki-service python

# View files
podman-compose exec pki-service ls -la /app/data
```

### View Resource Usage

```bash
# Container stats
podman stats pki-service config-service

# System-wide usage
podman system df
```

## 🛑 Stop and Clean Up

### Stop Services

```bash
# Stop services (keeps data)
podman-compose down

# Stop and remove volumes (WARNING: deletes all data!)
podman-compose down -v
```

### Clean Up Everything

```bash
# Stop and remove containers
podman-compose down

# Remove images
podman-compose down --rmi all

# Clean up data (optional - WARNING: deletes all certificates!)
rm -rf data/
```

## 🐛 Troubleshooting

### Services Won't Start

```bash
# Check logs for errors
podman-compose logs

# Rebuild containers
podman-compose build --no-cache
podman-compose up -d
```

### Permission Issues

```bash
# Fix ownership of data directories
sudo chown -R $UID:$GID data/

# For SELinux systems, relabel volumes
sudo chcon -R -t container_file_t data/
```

### Port Already in Use

```bash
# Check what's using the port
lsof -i :8000
lsof -i :8501

# Kill the process or change ports in .env
PKI_PORT=8080
CONFIG_PORT=8502
```

### Podman Machine Issues (macOS)

```bash
# Restart podman machine
podman machine stop
podman machine start

# Or recreate it
podman machine rm
podman machine init
podman machine start
```

### Container Won't Connect to Network

```bash
# Recreate networks
podman-compose down
podman network prune
podman-compose up -d
```

## 📝 Configuration

### Environment Variables

Edit `.env` to customize:

```bash
# Service ports
PKI_PORT=8000          # PKI service port
CONFIG_PORT=8501       # Streamlit UI port

# Certificate lifetimes
PKI_CERT_LIFETIME=3600  # Client cert lifetime (seconds)

# Logging
PKI_LOG_LEVEL=DEBUG     # DEBUG, INFO, WARNING, ERROR

# User mapping (for file permissions)
UID=1000
GID=1000
```

### Volume Mounts

Data is stored in these directories:

```
data/
├── pki/              # PKI data
│   ├── ca/           # Certificate authorities
│   │   ├── root_ca/
│   │   └── intermediate_cas/
│   └── certificates/ # Issued certificates
├── config/           # Configuration files
└── logs/             # Service logs
    ├── pki/
    └── config/
```

### Development Mode

To mount source code for live development:

```yaml
# Already configured in podman-compose.yml
volumes:
  - ./src:/app/src:ro  # Mount source code read-only
```

Changes to Python files will be reflected after restarting the service.

## 🔒 Security Notes

### Rootless Podman

Podman runs rootless by default, which is more secure than Docker:

- No root daemon
- User namespace isolation
- Better security isolation

### File Permissions

The containers run as your local user (UID:GID from .env), ensuring:

- Files are owned by you
- No permission issues
- Easier backup and access

### SELinux

On SELinux-enabled systems (Fedora, RHEL), you may need:

```bash
# Add :z for shared volumes
volumes:
  - ./data/pki:/app/data:z

# Or :Z for private volumes
volumes:
  - ./data/pki:/app/data:Z
```

## 📚 Additional Resources

- [Podman Documentation](https://docs.podman.io/)
- [Podman Compose GitHub](https://github.com/containers/podman-compose)
- [PKI Architecture](./pki-architecture.md)
- [Security Best Practices](./security-best-practices.md)

## 💡 Tips

### Faster Builds

```bash
# Use build cache
podman-compose build --parallel

# Skip build cache
podman-compose build --no-cache
```

### Persistent Logs

```bash
# Follow logs with timestamps
podman-compose logs -f --timestamps

# Save logs to file
podman-compose logs > logs.txt
```

### Container Cleanup

```bash
# Remove stopped containers
podman container prune

# Remove unused images
podman image prune

# Remove unused volumes
podman volume prune

# Clean everything
podman system prune -a
```

## 🎯 Next Steps

1. ✅ Get services running
2. ✅ Test certificate issuance
3. ✅ Explore the Streamlit UI
4. 📖 Read [PKI Architecture](./pki-architecture.md)
5. 🔒 Review [Security Analysis](./security-analysis.md)
6. 🧪 Run the test suite (see main README)
7. 🚀 Deploy to production (see deployment guide)

---

**Happy container orchestration with Podman!** 🐳✨
