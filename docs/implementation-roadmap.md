# PKI Implementation Roadmap

## Project Timeline: 4-6 Weeks

### Week 1: Foundation and Root CA Setup

#### Day 1-2: Environment Preparation
**Tasks:**
- [ ] Set up offline root CA system (air-gapped computer or VM)
- [ ] Install required tools: OpenSSL 3.0+, Python 3.11+, cryptography library
- [ ] Create directory structure for PKI components
- [ ] Document security procedures and policies

**Deliverables:**
- Offline root CA workstation configured
- Directory structure created
- Security policy documentation v1.0

**Tools Needed:**
```bash
# Install dependencies
apt-get install openssl python3 python3-pip
pip install cryptography>=42.0.0

# Create directory structure
mkdir -p /var/lib/console-auth/{root-ca,intermediary-ca,client}/{private,certs,crl,config}
chmod 700 /var/lib/console-auth/*/private
```

#### Day 3-4: Root CA Creation
**Tasks:**
- [ ] Generate root CA private key (RSA 4096 or EC P-384)
- [ ] Encrypt root CA key with strong passphrase
- [ ] Create self-signed root CA certificate (20-year validity)
- [ ] Calculate and document root CA pin (SHA-256 of public key)
- [ ] Create root CA OpenSSL configuration
- [ ] Execute and document signing ceremony

**Deliverables:**
- Root CA key pair (encrypted, stored offline)
- Root CA certificate (ca.cert.pem)
- Root CA pin hash documented
- Signing ceremony documentation

**Commands:**
```bash
# Generate root CA key (encrypted)
openssl genrsa -aes256 -out /var/lib/console-auth/root-ca/private/ca.key.pem 4096
chmod 400 /var/lib/console-auth/root-ca/private/ca.key.pem

# Create root CA certificate
openssl req -config /var/lib/console-auth/root-ca/config/openssl.cnf \
    -key /var/lib/console-auth/root-ca/private/ca.key.pem \
    -new -x509 -days 7300 -sha256 -extensions v3_ca \
    -out /var/lib/console-auth/root-ca/certs/ca.cert.pem

# Calculate pin
openssl x509 -in /var/lib/console-auth/root-ca/certs/ca.cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -hex > /var/lib/console-auth/root-ca/root-ca-pin.txt
```

#### Day 5: Testing and Validation
**Tasks:**
- [ ] Verify root CA certificate validity
- [ ] Test root CA signing capability
- [ ] Create backup of root CA materials
- [ ] Store encrypted backups in secure locations
- [ ] Document backup locations and recovery procedures

**Deliverables:**
- Verified root CA certificate
- Encrypted backups in 2+ locations
- Recovery procedures documented

---

### Week 2: Intermediary CA and Server Integration

#### Day 1-2: Intermediary CA Generation
**Tasks:**
- [ ] Generate intermediary CA private key (RSA 2048)
- [ ] Encrypt intermediary key with passphrase + TPM
- [ ] Create Certificate Signing Request (CSR)
- [ ] Transfer CSR to offline root CA system
- [ ] Sign intermediary CSR with root CA
- [ ] Verify intermediary certificate chain
- [ ] Calculate intermediary CA pin

**Deliverables:**
- Intermediary CA key pair
- Intermediary CA certificate signed by root
- Certificate chain file (intermediary + root)
- Intermediary pin documented

**Commands:**
```bash
# Generate intermediary CA key
openssl genrsa -aes256 -out /var/lib/console-auth/intermediary-ca/private/intermediary.key.pem 2048
chmod 400 /var/lib/console-auth/intermediary-ca/private/intermediary.key.pem

# Create CSR
openssl req -config /var/lib/console-auth/intermediary-ca/config/openssl.cnf \
    -new -sha256 -key /var/lib/console-auth/intermediary-ca/private/intermediary.key.pem \
    -out /var/lib/console-auth/intermediary-ca/csr/intermediary.csr.pem

# Transfer CSR to root CA system (USB)
# On root CA system:
openssl ca -config /var/lib/console-auth/root-ca/config/openssl.cnf \
    -extensions v3_intermediate_ca -days 1825 -notext -md sha256 \
    -in intermediary.csr.pem \
    -out intermediary.cert.pem

# Create chain file
cat /var/lib/console-auth/intermediary-ca/certs/intermediary.cert.pem \
    /var/lib/console-auth/root-ca/certs/ca.cert.pem \
    > /var/lib/console-auth/intermediary-ca/certs/chain.pem
```

#### Day 3-4: Server-Side Implementation
**Tasks:**
- [ ] Implement certificate issuance service (Python)
- [ ] Create API endpoints for certificate requests
- [ ] Implement authentication checks before issuance
- [ ] Configure 1-hour certificate TTL
- [ ] Implement certificate serial number tracking
- [ ] Set up audit logging

**Deliverables:**
- Certificate issuance service running
- API documentation
- Audit logging configured
- Unit tests for issuance logic

**Python Implementation:**
```python
# src/pki/certificate_issuer.py
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone
import secrets

class CertificateIssuer:
    def __init__(self, intermediary_key_path, intermediary_cert_path):
        # Load intermediary CA credentials
        with open(intermediary_key_path, 'rb') as f:
            self.ca_key = serialization.load_pem_private_key(
                f.read(),
                password=self._get_passphrase()
            )

        with open(intermediary_cert_path, 'rb') as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def issue_client_certificate(self, user_id, hostname):
        """Issue 1-hour client certificate"""
        # Implementation from pki-architecture.md
        pass
```

#### Day 5: Testing and Integration
**Tasks:**
- [ ] Test certificate issuance end-to-end
- [ ] Verify certificate chain validity
- [ ] Load test issuance service (100 requests/minute)
- [ ] Test certificate expiration (1-hour TTL)
- [ ] Integration testing with auth system

**Deliverables:**
- Passing integration tests
- Performance benchmarks documented
- Load testing results

---

### Week 3: Client-Side Implementation

#### Day 1-2: Certificate Validation Logic
**Tasks:**
- [ ] Implement certificate chain validator
- [ ] Implement certificate pinning (root + intermediary)
- [ ] Create pin verification logic
- [ ] Implement signature verification
- [ ] Add validity period checks
- [ ] Implement extension validation (KeyUsage, ExtendedKeyUsage)

**Deliverables:**
- Certificate validator module
- Pin verification working
- Unit tests for all validation scenarios

**Python Implementation:**
```python
# src/pki/certificate_validator.py
class CertificateValidator:
    def __init__(self, root_pin, intermediary_pin):
        self.root_pin = root_pin
        self.intermediary_pin = intermediary_pin

    def validate_client_certificate(self, cert_chain_pem):
        """Validate certificate with dual pinning"""
        # Implementation from pki-architecture.md
        pass
```

#### Day 3-4: Client Authentication Flow
**Tasks:**
- [ ] Implement certificate request workflow
- [ ] Add certificate renewal logic (before 1-hour expiry)
- [ ] Implement secure key storage (memory-only)
- [ ] Add certificate caching for session
- [ ] Implement automatic re-authentication

**Deliverables:**
- Client authentication library
- Automatic renewal working
- Memory-only key storage verified

**Client Flow:**
```
1. User authenticates (username/password)
2. Request client certificate from server
3. Receive certificate + private key
4. Store in memory (never persist to disk)
5. Use for authentication to services
6. Auto-renew at 50 minutes (before 1h expiry)
7. Clear from memory on logout
```

#### Day 5: Client Integration Testing
**Tasks:**
- [ ] Test complete authentication flow
- [ ] Test certificate renewal
- [ ] Test pin mismatch detection
- [ ] Test expired certificate handling
- [ ] Test network failures and retries

**Deliverables:**
- Passing end-to-end tests
- Client library documentation
- Example client implementation

---

### Week 4: Security Hardening and Operations

#### Day 1-2: Security Hardening
**Tasks:**
- [ ] Implement rate limiting on certificate issuance
- [ ] Add DDoS protection to issuance service
- [ ] Harden file permissions (0400 for private keys)
- [ ] Enable filesystem encryption (LUKS/FileVault)
- [ ] Implement TPM/Secure Enclave for key protection
- [ ] Add tamper detection for critical files

**Deliverables:**
- Security hardening checklist completed
- Penetration test plan
- Security audit report

**Security Measures:**
```bash
# File permissions
chmod 400 /var/lib/console-auth/*/private/*.key.pem
chown root:root /var/lib/console-auth/*/private/*.key.pem

# Rate limiting (iptables)
iptables -A INPUT -p tcp --dport 8443 -m limit --limit 100/minute --limit-burst 200 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP

# AppArmor/SELinux profiles
# (Create restrictive profiles for certificate service)
```

#### Day 3-4: Monitoring and Alerting
**Tasks:**
- [ ] Set up Prometheus metrics collection
- [ ] Create Grafana dashboards for PKI metrics
- [ ] Configure alerting rules (pin mismatch, high failure rate)
- [ ] Implement audit log aggregation (Elasticsearch/Splunk)
- [ ] Set up SIEM integration
- [ ] Create alerting runbooks

**Deliverables:**
- Monitoring dashboards live
- Alerting configured and tested
- Audit log pipeline operational
- On-call runbooks documented

**Metrics to Monitor:**
```yaml
metrics:
  - certificate_issuance_rate (per minute)
  - certificate_validation_success_rate (%)
  - certificate_validation_latency_p95 (ms)
  - pin_mismatch_count (should be 0)
  - certificate_expiry_warnings (count)
  - audit_log_events (per hour)
```

#### Day 5: Documentation and Training
**Tasks:**
- [ ] Create operational runbooks
- [ ] Document certificate renewal procedures
- [ ] Write incident response playbooks
- [ ] Create disaster recovery procedures
- [ ] Train operations team
- [ ] Conduct tabletop exercise (simulated incident)

**Deliverables:**
- Complete operational documentation
- Trained operations team
- Incident response playbooks
- Disaster recovery plan tested

---

### Week 5-6: Production Preparation and Deployment

#### Week 5: Pre-Production Testing

**Tasks:**
- [ ] Deploy to staging environment
- [ ] Conduct full security audit
- [ ] Penetration testing (red team exercise)
- [ ] Load testing (1000+ concurrent users)
- [ ] Chaos engineering (failure injection)
- [ ] Performance optimization based on results
- [ ] Fix all critical and high severity issues

**Deliverables:**
- Security audit report
- Penetration test results
- Performance benchmark results
- All critical issues resolved

**Testing Scenarios:**
```
1. Normal operation (happy path)
2. Certificate expiration and renewal
3. Pin mismatch (MITM simulation)
4. Compromised intermediary CA
5. High load (1000 certs/second)
6. Network failures and retries
7. Clock skew (time synchronization issues)
8. Certificate chain validation failures
```

#### Week 6: Production Deployment

**Phase 1: Limited Rollout (Days 1-2)**
- [ ] Deploy to 5% of users
- [ ] Monitor metrics closely
- [ ] Validate no errors or issues
- [ ] Collect user feedback

**Phase 2: Gradual Rollout (Days 3-4)**
- [ ] Increase to 25% of users
- [ ] Continue monitoring
- [ ] Address any issues immediately
- [ ] Optimize based on real-world usage

**Phase 3: Full Deployment (Day 5)**
- [ ] Deploy to 100% of users
- [ ] Monitor for 48 hours
- [ ] Document lessons learned
- [ ] Celebrate successful deployment! 🎉

**Rollback Plan:**
- [ ] Documented rollback procedure
- [ ] Tested rollback in staging
- [ ] One-command rollback script
- [ ] Communication plan for users

---

## Post-Deployment: Ongoing Operations

### Daily Tasks
- [ ] Monitor certificate issuance rate
- [ ] Check for validation failures
- [ ] Review audit logs for anomalies
- [ ] Verify backup integrity

### Weekly Tasks
- [ ] Review security alerts
- [ ] Analyze performance metrics
- [ ] Test certificate rotation
- [ ] Update documentation as needed

### Monthly Tasks
- [ ] Security audit review
- [ ] Review and update access controls
- [ ] Test disaster recovery procedures
- [ ] Certificate lifecycle analysis

### Quarterly Tasks
- [ ] Penetration testing
- [ ] Red team exercise
- [ ] Review and update security policies
- [ ] Training refresher for operations team

### Annual Tasks
- [ ] Comprehensive security audit
- [ ] Root CA health check
- [ ] Plan for certificate rotations
- [ ] Review compliance requirements
- [ ] Update threat model

---

## Risk Mitigation Plan

### High-Risk Scenarios

**1. Root CA Compromise**
- **Probability**: Very Low
- **Impact**: Critical
- **Mitigation**: Offline storage, multi-party authorization, HSM
- **Detection**: Audit log monitoring, tamper-evident storage
- **Response**: Emergency revocation, re-issuance plan, forensic investigation

**2. Intermediary CA Compromise**
- **Probability**: Low
- **Impact**: High
- **Mitigation**: Encrypted storage, access controls, monitoring
- **Detection**: Anomalous certificate issuance, audit logs
- **Response**: Immediate revocation, new intermediary issuance, user notification

**3. Certificate Pin Bypass (MITM)**
- **Probability**: Very Low (with proper implementation)
- **Impact**: High
- **Mitigation**: Dual pinning (root + intermediary), pin update verification
- **Detection**: Pin mismatch alerts
- **Response**: Immediate investigation, user notification, potential rollback

**4. Certificate Theft**
- **Probability**: Medium
- **Impact**: Low (due to 1-hour TTL)
- **Mitigation**: Memory-only storage, short TTL, automatic rotation
- **Detection**: Concurrent use from multiple IPs
- **Response**: Emergency revocation (in-memory blacklist), user notification

---

## Success Metrics

### Security Metrics
- ✅ Zero successful MITM attacks
- ✅ Pin mismatch rate < 0.01%
- ✅ Certificate validation success rate > 99.9%
- ✅ No root CA unauthorized access
- ✅ Incident response time < 15 minutes

### Performance Metrics
- ✅ Certificate issuance latency < 100ms (p95)
- ✅ Certificate validation latency < 50ms (p95)
- ✅ Support 1000+ concurrent certificate issuances
- ✅ 99.99% service uptime

### Operational Metrics
- ✅ Mean Time to Detect (MTTD) < 5 minutes
- ✅ Mean Time to Respond (MTTR) < 30 minutes
- ✅ Zero audit log gaps
- ✅ 100% operations team trained

---

## Budget and Resources

### Hardware/Software
- Offline root CA system: $2,000 (or use air-gapped VM)
- HSM (optional): $5,000 - $50,000
- Server infrastructure: $500/month (cloud hosting)
- Monitoring tools: $200/month (Prometheus/Grafana)
- SIEM integration: $500/month

### Personnel
- Security engineer: 40 hours (weeks 1-2)
- Backend developer: 80 hours (weeks 2-4)
- DevOps engineer: 60 hours (weeks 4-6)
- QA engineer: 40 hours (week 5)
- Security auditor: 20 hours (external)

### Total Estimated Cost
- One-time: $5,000 - $55,000 (depending on HSM)
- Monthly: $1,200
- Personnel: ~$30,000 (assuming $150/hour average)

---

## Dependencies and Prerequisites

### Technical Dependencies
- OpenSSL 3.0+ installed
- Python 3.11+ with cryptography library
- Secure server infrastructure (hardened OS)
- Network infrastructure (firewalls, load balancers)
- Monitoring stack (Prometheus, Grafana)
- Audit log pipeline (Elasticsearch or similar)

### Organizational Dependencies
- Security policy approval
- Budget approval
- Operations team availability
- Access to offline root CA system
- Backup storage locations identified

### External Dependencies
- Certificate policy review (legal/compliance)
- Penetration testing vendor (if external)
- HSM vendor (if applicable)
- SIEM vendor integration

---

## Conclusion

This roadmap provides a comprehensive 4-6 week plan for implementing a production-ready PKI infrastructure for secure console authentication. The phased approach ensures proper testing, security hardening, and gradual rollout to minimize risk.

**Key Success Factors:**
1. ✅ Offline root CA with strong protection
2. ✅ Comprehensive testing at each phase
3. ✅ Security-first approach throughout
4. ✅ Thorough monitoring and alerting
5. ✅ Well-trained operations team
6. ✅ Documented procedures and runbooks

**Next Steps:**
1. Review and approve this roadmap
2. Allocate budget and resources
3. Assign team members to tasks
4. Begin Week 1: Foundation and Root CA Setup
5. Execute according to timeline with regular checkpoints

Good luck with your PKI implementation! 🔐
