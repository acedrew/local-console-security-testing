# Secrets Management Guide

## Overview

This document describes the secure management of secrets for the PKI infrastructure, including certificates, private keys, API credentials, and other sensitive data.

## Secrets Hierarchy

### Critical Secrets (Tier 1)
**Maximum Security Required**

1. **CA Private Key** (`ca-private-key.pem`)
   - Most critical secret in the system
   - Compromise = complete infrastructure breach
   - Storage: HSM (production) or encrypted volume (development)
   - Access: Multi-person authorization required
   - Backup: Split-knowledge escrow, offline storage

2. **CA Certificate** (`ca-certificate.pem`)
   - Public key of the CA
   - Less sensitive than private key, but controls trust
   - Storage: Version controlled, distributed securely
   - Access: Read-only for most services

### High-Value Secrets (Tier 2)
**Strong Protection Required**

1. **Server TLS Private Keys**
   - `server-key.pem` (PKI service)
   - `mqtt-server-key.pem` (MQTT broker)
   - Storage: Docker secrets or encrypted volumes
   - Rotation: Every 90 days

2. **MQTT Broker Credentials** (`mqtt-credentials.json`)
   - Service account passwords
   - API tokens
   - Storage: Docker secrets
   - Rotation: Every 30 days

### Moderate Secrets (Tier 3)
**Standard Protection**

1. **Configuration Encryption Keys**
   - Database encryption keys
   - Configuration file encryption
   - Storage: Environment variables (encrypted)
   - Rotation: Every 90 days

## Storage Methods

### Production: Docker Swarm Secrets

```bash
# Create a secret from a file
echo "secret-value" | docker secret create ca_private_key -

# Create from existing file
docker secret create ca_private_key /path/to/ca-key.pem

# List secrets
docker secret ls

# Remove secret
docker secret rm ca_private_key
```

**Access in containers:**
```yaml
services:
  pki-service:
    secrets:
      - ca_private_key

secrets:
  ca_private_key:
    external: true
```

Secrets are mounted at `/run/secrets/<secret_name>` inside containers.

### Production: Kubernetes Secrets

```bash
# Create secret from file
kubectl create secret generic ca-private-key \
  --from-file=ca-key.pem=/path/to/ca-key.pem

# Create secret from literal
kubectl create secret generic mqtt-credentials \
  --from-literal=username=pki-service \
  --from-literal=password='SecureP@ssw0rd'

# List secrets
kubectl get secrets

# Describe secret (values are base64 encoded)
kubectl describe secret ca-private-key
```

**Access in pods:**
```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: pki-service
    volumeMounts:
    - name: ca-key
      mountPath: "/secrets"
      readOnly: true
  volumes:
  - name: ca-key
    secret:
      secretName: ca-private-key
```

### Production: HashiCorp Vault

```bash
# Store secret in Vault
vault kv put secret/pki/ca-private-key value=@/path/to/ca-key.pem

# Read secret
vault kv get secret/pki/ca-private-key

# Enable dynamic secrets for database
vault secrets enable database

# Configure PKI secrets engine
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki
```

**Integration with Docker:**
```yaml
services:
  pki-service:
    environment:
      - VAULT_ADDR=https://vault.example.com:8200
      - VAULT_TOKEN=${VAULT_TOKEN}
    command:
      - sh
      - -c
      - |
        # Retrieve secrets from Vault
        export CA_KEY=$(vault kv get -field=value secret/pki/ca-private-key)
        exec python -m uvicorn main:app
```

### Development: Encrypted Files

```bash
# Generate encryption key
openssl rand -base64 32 > .encryption-key

# Encrypt secret file
openssl enc -aes-256-cbc -salt \
  -in ca-private-key.pem \
  -out ca-private-key.pem.enc \
  -pass file:.encryption-key

# Decrypt at runtime
openssl enc -d -aes-256-cbc \
  -in ca-private-key.pem.enc \
  -out ca-private-key.pem \
  -pass file:.encryption-key
```

**Never commit `.encryption-key` to version control!**

## Secret Generation

### CA Private Key

```bash
# ECDSA P-384 (Recommended)
openssl ecparam -name secp384r1 -genkey -noout -out ca-private-key.pem

# RSA 4096 (Alternative)
openssl genrsa -out ca-private-key.pem 4096

# Protect with passphrase (production)
openssl ecparam -name secp384r1 -genkey | \
  openssl ec -aes256 -out ca-private-key.pem
```

### CA Certificate

```bash
# Self-signed root CA
openssl req -new -x509 -days 3650 -key ca-private-key.pem \
  -out ca-certificate.pem \
  -subj "/C=US/ST=CA/L=San Francisco/O=Example Org/CN=Local Console PKI Root CA"
```

### Server TLS Certificates

```bash
# Generate server private key
openssl ecparam -name secp384r1 -genkey -noout -out server-key.pem

# Create certificate signing request
openssl req -new -key server-key.pem -out server.csr \
  -subj "/C=US/ST=CA/L=San Francisco/O=Example Org/CN=pki-service"

# Sign with CA
openssl x509 -req -days 365 -in server.csr \
  -CA ca-certificate.pem -CAkey ca-private-key.pem \
  -CAcreateserial -out server-cert.pem \
  -extfile <(printf "subjectAltName=DNS:pki-service,DNS:localhost,IP:127.0.0.1")
```

### MQTT Credentials

```bash
# Generate random password
openssl rand -base64 32 > mqtt-password.txt

# Create credentials JSON
cat > mqtt-credentials.json <<EOF
{
  "username": "pki-service",
  "password": "$(cat mqtt-password.txt)"
}
EOF

# Secure permissions
chmod 600 mqtt-credentials.json
```

## Secret Rotation

### Automated Rotation Schedule

| Secret | Rotation Frequency | Automation |
|--------|-------------------|------------|
| CA Private Key | 1-2 years | Manual (key ceremony) |
| Server TLS Keys | 90 days | Automated |
| MQTT Credentials | 30 days | Automated |
| API Keys | 90 days | Automated |
| Encryption Keys | 90 days | Automated |

### Rotation Procedure

1. **Generate New Secret**
   ```bash
   ./scripts/generate-secret.sh server-key-new.pem
   ```

2. **Deploy New Secret (Blue-Green)**
   ```bash
   # Add new secret alongside old
   docker secret create server_key_new server-key-new.pem

   # Update service to use both
   docker service update \
     --secret-add server_key_new \
     pki-service
   ```

3. **Test New Secret**
   ```bash
   # Verify service functionality
   curl -k https://localhost:8443/health
   ```

4. **Switch to New Secret**
   ```bash
   # Update configuration to use new secret
   # Deploy updated service

   # Remove old secret after grace period
   docker secret rm server_key_old
   ```

5. **Audit and Log**
   ```bash
   # Record rotation in audit log
   echo "$(date -Iseconds): Rotated server_key" >> /var/log/secret-rotation.log
   ```

## Secret Access Control

### File Permissions

```bash
# Secrets directory
chmod 700 /path/to/secrets/
chown root:root /path/to/secrets/

# Individual secret files
chmod 600 /path/to/secrets/ca-private-key.pem
chown root:root /path/to/secrets/ca-private-key.pem
```

### Docker Secret Permissions

Docker secrets are mounted with these permissions automatically:
- Owner: Root (UID 0)
- Permissions: 0444 (read-only)
- Location: `/run/secrets/<secret_name>`

### User Mapping

```dockerfile
# In Dockerfile, switch to non-root user
USER pki:pki

# Secrets are still accessible (mounted by Docker daemon)
# But cannot be modified
```

## Backup and Recovery

### Backup Strategy

```bash
#!/bin/bash
# backup-secrets.sh

BACKUP_DIR="/secure/backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup CA private key (split-knowledge)
./split-secret.sh /secrets/ca-private-key.pem "$BACKUP_DIR/ca-key-" 3 5

# Backup other secrets (encrypted)
tar czf - /secrets/*.pem | \
  openssl enc -aes-256-cbc -salt -pbkdf2 \
  -out "$BACKUP_DIR/secrets-backup.tar.gz.enc"

# Store checksum
sha256sum "$BACKUP_DIR"/* > "$BACKUP_DIR/SHA256SUMS"

# Upload to offline storage
# (manual step or secure automated process)
```

### Recovery Procedure

```bash
#!/bin/bash
# recover-secrets.sh

BACKUP_DIR="/secure/backups/20251107-120000"

# Verify checksums
cd "$BACKUP_DIR"
sha256sum -c SHA256SUMS || exit 1

# Recover CA private key (requires 3 of 5 key holders)
./combine-secret.sh "$BACKUP_DIR/ca-key-"* /secrets/ca-private-key.pem

# Recover other secrets
openssl enc -d -aes-256-cbc -pbkdf2 \
  -in secrets-backup.tar.gz.enc | \
  tar xzf - -C /

# Set correct permissions
chmod 600 /secrets/*.pem
chown root:root /secrets/*.pem
```

## Environment Variables (NOT for Secrets!)

**Never store secrets in environment variables.** They are:
- Visible in `docker inspect`
- Visible in `/proc/<pid>/environ`
- Logged in many systems
- Inherited by child processes

**Use environment variables only for:**
- Feature flags
- Non-sensitive configuration
- References to secret paths

```yaml
# ✅ GOOD: Reference to secret location
environment:
  - CA_KEY_PATH=/run/secrets/ca_private_key

# ❌ BAD: Secret value in environment
environment:
  - CA_KEY=LS0tLS1CRUdJTi...
```

## Development vs Production

### Development Setup

```bash
# Create development secrets directory
mkdir -p .dev-secrets
chmod 700 .dev-secrets

# Generate development keys (with weak/no passphrase)
./scripts/generate-dev-secrets.sh

# Use docker-compose with file-based secrets
docker-compose -f docker-compose.dev.yml up
```

### Production Setup

```bash
# Use external secrets management
docker-compose -f docker-compose.prod.yml up

# Secrets are externalized (Vault, AWS Secrets Manager, etc.)
```

## Compliance Requirements

### SOC 2 / ISO 27001

- ✅ Encryption at rest (AES-256)
- ✅ Encryption in transit (TLS 1.3)
- ✅ Access control (RBAC)
- ✅ Audit logging (all secret access)
- ✅ Regular rotation (automated)
- ✅ Secure backup (encrypted, offsite)

### NIST 800-53

- ✅ IA-5: Authenticator Management
- ✅ SC-12: Cryptographic Key Establishment
- ✅ SC-13: Cryptographic Protection
- ✅ SC-17: Public Key Infrastructure Certificates

## Monitoring and Alerting

### Metrics to Track

```yaml
# Prometheus metrics
secret_rotation_timestamp{secret="ca_private_key"}
secret_access_total{secret="server_key",user="pki-service"}
secret_rotation_failures_total
```

### Alerts

```yaml
# Alert when secret hasn't been rotated
- alert: SecretRotationOverdue
  expr: (time() - secret_rotation_timestamp) > 7776000  # 90 days
  severity: warning

# Alert on secret access from unexpected user
- alert: UnauthorizedSecretAccess
  expr: secret_access_total{user!~"pki-service|config-service"}
  severity: critical
```

## Troubleshooting

### Secret Not Found

```bash
# Check if secret exists
docker secret ls | grep ca_private_key

# Verify secret is accessible in container
docker exec pki-service ls -la /run/secrets/

# Check container logs
docker logs pki-service
```

### Permission Denied

```bash
# Check file permissions
docker exec pki-service ls -l /run/secrets/ca_private_key

# Verify user running process
docker exec pki-service whoami

# Check AppArmor/SELinux denials
ausearch -m avc -ts recent
```

### Secret Corruption

```bash
# Verify secret content
docker secret inspect ca_private_key

# Compare with backup
sha256sum /run/secrets/ca_private_key
sha256sum /backup/ca-private-key.pem

# Restore from backup if needed
docker secret rm ca_private_key
docker secret create ca_private_key /backup/ca-private-key.pem
```

## Best Practices Summary

✅ **DO:**
- Use Docker secrets or Kubernetes secrets in production
- Rotate secrets regularly (automated)
- Encrypt secrets at rest
- Use TLS for secrets in transit
- Implement least-privilege access
- Audit all secret access
- Backup secrets securely (split-knowledge for CA key)
- Use strong cryptographic algorithms
- Monitor secret rotation status

❌ **DON'T:**
- Store secrets in environment variables
- Commit secrets to version control
- Store secrets in Docker images
- Share secrets between environments
- Use default/example secrets in production
- Grant broad secret access
- Reuse secrets across systems
- Store secrets in plaintext
- Disable secret rotation

## Additional Resources

- [Docker Secrets Documentation](https://docs.docker.com/engine/swarm/secrets/)
- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [NIST SP 800-57: Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
