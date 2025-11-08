# Configuration and Deployment Guide

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 2GB available RAM
- 10GB available disk space

### Initial Setup

1. **Copy environment template:**
   ```bash
   cp config/.env.template config/.env
   ```

2. **Generate secrets:**
   ```bash
   ./scripts/generate-secrets.sh
   ```

3. **Create required directories:**
   ```bash
   mkdir -p data/{pki,certificates,mqtt,mqtt-certs} logs/{pki,mqtt,config}
   chmod 700 secrets/
   chmod 755 data/ logs/
   ```

4. **Build and start services:**
   ```bash
   docker-compose -f config/docker-compose.yml build
   docker-compose -f config/docker-compose.yml up -d
   ```

5. **Verify health:**
   ```bash
   docker-compose -f config/docker-compose.yml ps
   docker-compose -f config/docker-compose.yml logs -f
   ```

## Directory Structure

```
local-console-security-testing/
├── config/                      # Configuration files
│   ├── docker-compose.yml       # Container orchestration
│   ├── .env.template            # Environment template
│   ├── .env                     # Environment config (not in git)
│   ├── security-config.yml      # Security policies
│   ├── secrets-management.md    # Secrets documentation
│   └── mosquitto/               # MQTT broker config
│       ├── mosquitto.conf       # Broker configuration
│       └── acl.conf             # Access control lists
├── docker/                      # Dockerfiles
│   ├── pki-service.Dockerfile   # PKI service image
│   └── config-service.Dockerfile # Config service image
├── data/                        # Persistent data (not in git)
│   ├── pki/                     # PKI database
│   ├── certificates/            # Issued certificates
│   ├── mqtt/                    # MQTT persistence
│   └── mqtt-certs/              # MQTT TLS certificates
├── logs/                        # Service logs (not in git)
│   ├── pki/                     # PKI service logs
│   ├── mqtt/                    # MQTT broker logs
│   └── config/                  # Config service logs
├── secrets/                     # Sensitive files (not in git)
│   ├── ca-private-key.pem       # CA private key
│   ├── ca-certificate.pem       # CA certificate
│   ├── server-key.pem           # Server TLS key
│   ├── server-cert.pem          # Server TLS cert
│   └── mqtt-credentials.json    # MQTT credentials
└── docs/                        # Documentation
    └── security-analysis.md     # Security analysis
```

## Configuration Files

### docker-compose.yml

Main orchestration file defining:
- **pki-service**: Certificate authority and management
- **config-service**: Configuration validation and management
- **mqtt-broker**: Device verification broker

**Security features:**
- Read-only root filesystems
- Non-root users
- Capability dropping
- Resource limits
- Network isolation
- Secrets management

### .env

Environment variables for configuration. **Never commit to git!**

Key settings:
- `PKI_CERT_LIFETIME`: Certificate lifetime in seconds
- `PKI_CERT_ALGORITHM`: Cryptographic algorithm (ECDSA/RSA)
- `MQTT_VERIFY_ENABLED`: Enable dual verification
- `AUDIT_LOG_ENABLED`: Enable audit logging

### security-config.yml

Comprehensive security policies:
- Certificate policies and validation rules
- TLS/SSL configuration
- Access control and authorization
- Rate limiting
- Audit logging
- Compliance requirements
- Incident response procedures

## Services

### PKI Service (port 8443)

**Purpose:** Certificate authority and certificate management

**Endpoints:**
- `POST /api/v1/certificates/issue` - Issue new certificate
- `POST /api/v1/certificates/revoke` - Revoke certificate
- `GET /api/v1/certificates/verify` - Verify certificate
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics

**Configuration:**
- Environment: See `.env` file
- Secrets: CA keys, server TLS, MQTT credentials
- Volumes: `/app/data`, `/app/certs`, `/app/logs`

**Resource Limits:**
- CPU: 2.0 cores (limit), 0.5 cores (reservation)
- Memory: 1GB (limit), 256MB (reservation)

### Config Service

**Purpose:** Configuration validation and management

**Features:**
- Validates configuration on startup
- Watches for configuration changes
- Provides configuration templates
- Ensures policy compliance

**Configuration:**
- No exposed ports (internal only)
- Read-only access to config files
- Writable logs and templates

**Resource Limits:**
- CPU: 0.5 cores (limit), 0.1 cores (reservation)
- Memory: 256MB (limit), 64MB (reservation)

### MQTT Broker (port 8883)

**Purpose:** Device verification and authorization

**Features:**
- TLS 1.3 encryption
- Client certificate authentication
- Topic-level access control (ACLs)
- Persistent message storage

**Configuration:**
- See `config/mosquitto/mosquitto.conf`
- ACLs in `config/mosquitto/acl.conf`
- Certificates in `/mosquitto/certs`

**Resource Limits:**
- CPU: 1.0 cores (limit), 0.25 cores (reservation)
- Memory: 512MB (limit), 128MB (reservation)

## Networks

### pki_internal (172.20.0.0/24)

Internal network for service-to-service communication.
No external access allowed.

**Connected services:**
- pki-service
- config-service
- mqtt-broker

### pki_external (172.21.0.0/24)

External network for client access to PKI service.

**Connected services:**
- pki-service

### mqtt_network (172.22.0.0/24)

MQTT-specific network for broker isolation.

**Connected services:**
- pki-service (client)
- mqtt-broker

## Volumes

### Persistent Volumes (Backed Up)

- `pki_certificates`: Issued certificates
- `pki_data`: Certificate database
- `mqtt_data`: MQTT message persistence

**Backup schedule:** Hourly

### Log Volumes (Not Backed Up)

- `pki_logs`: PKI service logs
- `config_logs`: Config service logs
- `mqtt_logs`: MQTT broker logs

**Retention:** 30 days, automatic rotation

## Secrets

Secrets are managed via Docker secrets (production) or encrypted files (development).

**Critical secrets:**
- `ca_private_key`: CA private key (NEVER expose!)
- `ca_certificate`: CA public certificate
- `server_key`: Server TLS private key
- `server_cert`: Server TLS certificate
- `mqtt_credentials`: MQTT authentication

**Location in containers:** `/run/secrets/<secret_name>`

**Permissions:** 0444 (read-only), owned by root

See `config/secrets-management.md` for detailed documentation.

## Deployment Scenarios

### Development

```bash
# Use development environment
cp config/.env.template config/.env.dev
export ENV_FILE=config/.env.dev

# Generate development secrets (weak passphrases)
./scripts/generate-dev-secrets.sh

# Start with hot-reload
docker-compose -f config/docker-compose.yml \
  -f config/docker-compose.dev.yml up
```

### Staging

```bash
# Use staging environment
cp config/.env.template config/.env.staging
export ENV_FILE=config/.env.staging

# Generate staging secrets
./scripts/generate-secrets.sh --environment staging

# Deploy to staging swarm
docker stack deploy -c config/docker-compose.yml pki-staging
```

### Production

```bash
# Use production environment
cp config/.env.template config/.env.prod
export ENV_FILE=config/.env.prod

# Initialize external secrets (Vault, AWS SM, etc.)
./scripts/init-external-secrets.sh

# Deploy to production swarm with high availability
docker stack deploy -c config/docker-compose.yml \
  -c config/docker-compose.prod.yml pki-production

# Scale for high availability
docker service scale pki-production_pki-service=3
docker service scale pki-production_mqtt-broker=3
```

## Monitoring

### Health Checks

```bash
# Check all services
docker-compose -f config/docker-compose.yml ps

# Check specific service
curl -k https://localhost:8443/health

# MQTT broker health
docker exec mqtt-broker mosquitto_sub -t '$SYS/broker/uptime' -C 1
```

### Metrics

Prometheus metrics available at:
- PKI Service: `https://localhost:9090/metrics`

**Key metrics:**
- `certificates_issued_total`: Total certificates issued
- `certificates_revoked_total`: Total certificates revoked
- `certificate_validation_failures_total`: Validation failures
- `certificate_issuance_duration_seconds`: Issuance latency
- `active_certificates`: Currently active certificates

### Logs

```bash
# View all logs
docker-compose -f config/docker-compose.yml logs -f

# View specific service
docker-compose -f config/docker-compose.yml logs -f pki-service

# Search logs
docker-compose -f config/docker-compose.yml logs pki-service | grep ERROR

# Export logs
docker-compose -f config/docker-compose.yml logs --no-color > logs-export.txt
```

### Audit Logs

Audit logs are stored in `/app/logs/audit.log` with JSON format.

**View audit events:**
```bash
docker exec pki-service tail -f /app/logs/audit.log | jq '.'

# Filter by event type
docker exec pki-service cat /app/logs/audit.log | \
  jq 'select(.event_type == "certificate_issued")'

# Export audit logs
docker exec pki-service cat /app/logs/audit.log > audit-export.json
```

## Troubleshooting

### Service Won't Start

1. **Check logs:**
   ```bash
   docker-compose -f config/docker-compose.yml logs pki-service
   ```

2. **Verify secrets:**
   ```bash
   docker secret ls
   ls -la secrets/
   ```

3. **Check permissions:**
   ```bash
   ls -l data/ logs/ secrets/
   ```

4. **Validate configuration:**
   ```bash
   docker run --rm -v $(pwd)/config:/config pki-service \
     python -m config.validator --config /config/security-config.yml
   ```

### Certificate Issuance Fails

1. **Check CA availability:**
   ```bash
   docker exec pki-service ls -la /run/secrets/ca_private_key
   ```

2. **Verify MQTT broker connection:**
   ```bash
   docker logs mqtt-broker
   docker exec pki-service nc -zv mqtt-broker 8883
   ```

3. **Check rate limits:**
   ```bash
   docker exec pki-service cat /app/logs/pki.log | grep "rate_limit"
   ```

### MQTT Broker Issues

1. **Check broker status:**
   ```bash
   docker exec mqtt-broker mosquitto_sub -t '$SYS/#' -v
   ```

2. **Verify TLS configuration:**
   ```bash
   docker exec mqtt-broker ls -la /run/secrets/
   docker exec mqtt-broker cat /mosquitto/config/mosquitto.conf
   ```

3. **Test connection:**
   ```bash
   mosquitto_sub -h localhost -p 8883 \
     --cafile secrets/mqtt-ca-cert.pem \
     --cert secrets/client-cert.pem \
     --key secrets/client-key.pem \
     -t 'test/topic' -v
   ```

### High Resource Usage

1. **Check resource consumption:**
   ```bash
   docker stats
   ```

2. **Review metrics:**
   ```bash
   curl -k https://localhost:9090/metrics
   ```

3. **Adjust resource limits in docker-compose.yml**

### Network Connectivity Issues

1. **Check network configuration:**
   ```bash
   docker network ls
   docker network inspect pki_internal
   ```

2. **Test connectivity:**
   ```bash
   docker exec pki-service ping -c 3 mqtt-broker
   docker exec pki-service nc -zv mqtt-broker 8883
   ```

3. **Check firewall rules:**
   ```bash
   sudo iptables -L -n
   ```

## Maintenance

### Regular Tasks

**Daily:**
- Monitor health checks
- Review error logs
- Check disk space

**Weekly:**
- Review audit logs
- Analyze metrics trends
- Check certificate issuance rate

**Monthly:**
- Rotate secrets (automated)
- Review security policies
- Update dependencies
- Run vulnerability scans

**Quarterly:**
- Security audit
- Performance review
- Disaster recovery test
- Update documentation

### Backup Procedures

**Automated backups:**
```bash
# Backup script runs via cron
0 */6 * * * /opt/pki/scripts/backup.sh
```

**Manual backup:**
```bash
./scripts/backup.sh --manual
```

**Restore from backup:**
```bash
./scripts/restore.sh /backups/2025-11-07-120000
```

### Updates and Patching

**Update Docker images:**
```bash
docker-compose -f config/docker-compose.yml pull
docker-compose -f config/docker-compose.yml up -d --no-deps --build
```

**Update configuration:**
```bash
# Edit configuration
vi config/security-config.yml

# Validate
docker run --rm -v $(pwd)/config:/config pki-service \
  python -m config.validator --config /config/security-config.yml

# Reload (graceful)
docker-compose -f config/docker-compose.yml kill -s SIGHUP pki-service
```

## Security Checklist

Before deploying to production:

- [ ] All secrets stored securely (Docker secrets, Vault, etc.)
- [ ] `.env` file has secure permissions (0600)
- [ ] `.env` file is in `.gitignore`
- [ ] TLS 1.3 enforced in all services
- [ ] Certificate lifetime ≤ 15 minutes
- [ ] MQTT verification enabled
- [ ] Audit logging enabled
- [ ] Monitoring and alerting configured
- [ ] Backups automated and tested
- [ ] Resource limits configured
- [ ] Network isolation implemented
- [ ] Non-root users in all containers
- [ ] Read-only root filesystems where possible
- [ ] Capabilities dropped to minimum
- [ ] Security scanning in CI/CD pipeline
- [ ] Incident response plan documented
- [ ] Disaster recovery tested
- [ ] All development features disabled
- [ ] Strong cryptographic algorithms (ECDSA P-384 or RSA 4096)
- [ ] Rate limiting enabled and tested

## Additional Resources

- [Security Analysis](../docs/security-analysis.md)
- [Secrets Management](config/secrets-management.md)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [MQTT Security](https://www.hivemq.com/mqtt-security-fundamentals/)
- [TLS Configuration](https://wiki.mozilla.org/Security/Server_Side_TLS)
