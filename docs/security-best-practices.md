# Security Best Practices Summary - PKI Implementation

## Critical Security Requirements

### 1. Root CA Protection (HIGHEST PRIORITY)

**Key Storage:**
- ✅ Store offline on air-gapped system
- ✅ Encrypt with AES-256 + strong passphrase (20+ chars)
- ✅ Use HSM (FIPS 140-2 Level 3+) if budget allows
- ✅ Keep encrypted backups in 2+ geographic locations
- ✅ Implement Shamir Secret Sharing (2-of-3 custodians)

**Access Control:**
- ✅ Require multi-party authorization (M-of-N scheme)
- ✅ Document all signing ceremonies with witnesses
- ✅ Maintain tamper-evident audit log
- ✅ Time-lock safe for emergency access

**Operational Security:**
- ✅ NEVER connect root CA system to network
- ✅ Boot from read-only media for signing
- ✅ Use USB transfer for CSRs (verify checksums)
- ✅ Limit signing to 1-2 times per year

### 2. Intermediary CA Security

**Key Protection:**
- ✅ Encrypt with passphrase + TPM/Secure Enclave
- ✅ File permissions: 0400 (owner read-only)
- ✅ Store on encrypted filesystem (LUKS/FileVault)
- ✅ One intermediary per server/service

**Operational Controls:**
- ✅ Rate limit certificate issuance (e.g., 100/hour max)
- ✅ Monitor for anomalous issuance patterns
- ✅ Log all certificate operations
- ✅ Implement automatic key rotation alerts (< 30 days to expiry)

### 3. Client Certificate Security

**Issuance:**
- ✅ Authenticate user before issuing
- ✅ Use 1-hour TTL (no revocation infrastructure needed)
- ✅ Generate unique serial numbers (cryptographically random)
- ✅ Log: timestamp, user, IP, hostname

**Storage:**
- ✅ NEVER persist client private key to disk
- ✅ Store in memory only during session
- ✅ Clear key material on logout/timeout
- ✅ Use secure memory allocation (mlock)

### 4. Certificate Validation

**Chain Verification:**
- ✅ Validate complete chain: client → intermediary → root
- ✅ Verify cryptographic signatures at each level
- ✅ Check validity periods strictly (no clock skew tolerance)
- ✅ Verify certificate extensions (KeyUsage, ExtendedKeyUsage)

**Certificate Pinning:**
- ✅ Pin both root CA and intermediary CA public keys
- ✅ Use SHA-256 hashing for pins
- ✅ Embed pins in code-signed binaries
- ✅ Require manual verification for pin updates
- ✅ Include 2-3 backup pins for rotation

**Pin Calculation:**
```bash
# Calculate SHA-256 pin of certificate public key
openssl x509 -in cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -hex
```

### 5. Cryptographic Standards (2025)

**Approved Algorithms:**
- ✅ **Signatures**: RSA-PSS (2048+ bits) or ECDSA (P-256, P-384)
- ✅ **Hashing**: SHA-256, SHA-384, SHA-512
- ✅ **Encryption**: AES-256-GCM, ChaCha20-Poly1305
- ✅ **Key Exchange**: ECDH (P-256, P-384, X25519)

**Prohibited Algorithms:**
- ❌ SHA-1, MD5 (broken)
- ❌ RSA < 2048 bits (insufficient strength)
- ❌ DES, 3DES (deprecated)
- ❌ RC4 (insecure)

**Key Sizes:**
- Root CA: RSA 4096 or EC P-384
- Intermediary CA: RSA 2048 or EC P-256
- Client Cert: RSA 2048 or EC P-256

### 6. Certificate Lifecycle

**Validity Periods:**
- Root CA: 10-20 years
- Intermediary CA: 2-5 years
- Client Certificate: 1 hour

**Rotation Schedule:**
- Root CA: Plan 2 years before expiry
- Intermediary CA: Renew 3 months before expiry
- Client Certificate: Auto-renew every hour (transparent to user)

**Revocation:**
- Root CA: Publish to CRL immediately if compromised
- Intermediary CA: Emergency blacklist + CRL update within 1 hour
- Client Certificate: No revocation needed (1-hour TTL sufficient)

### 7. Monitoring and Alerting

**Critical Alerts (Immediate Action):**
- 🚨 Certificate pin mismatch (MITM attack)
- 🚨 Root CA private key accessed
- 🚨 Intermediary CA signing > 1000 certs/hour
- 🚨 Certificate chain validation failures > 1%

**Warning Alerts (Investigate Within 24h):**
- ⚠️ Intermediary CA expiring < 30 days
- ⚠️ Certificate issuance rate anomaly
- ⚠️ Repeated validation failures from same IP
- ⚠️ Root CA expiring < 180 days

**Audit Logging Requirements:**
- Log all certificate issuances (who, when, what)
- Log all validation attempts (success and failure)
- Log all CA key access events
- Log all pin mismatches
- Retain logs for 1+ year (compliance requirement)

### 8. Incident Response Procedures

**Compromised Client Certificate:**
1. Add serial number to emergency blacklist (in-memory)
2. Wait 1 hour for automatic expiry
3. Investigate compromise source
4. Reset user credentials if needed

**Compromised Intermediary CA:**
1. Immediately disable certificate issuance
2. Add intermediary serial to root CA CRL
3. Generate new intermediary CA
4. Notify all clients to update pins
5. Investigate breach thoroughly
6. Forensic analysis of issued certificates

**Compromised Root CA (WORST CASE):**
1. Initiate emergency response team
2. Revoke root CA immediately
3. Publish to all CRL distribution points
4. Generate new root CA (offline ceremony)
5. Re-issue all intermediary CAs
6. Coordinate client pin updates
7. Full security audit and remediation
8. Legal/regulatory notifications if required

### 9. Testing and Validation

**Pre-Production Testing:**
- ✅ Test certificate chain validation with expired certs
- ✅ Test pin mismatch detection (MITM simulation)
- ✅ Test certificate rotation under load
- ✅ Test emergency revocation procedures
- ✅ Penetration testing of PKI infrastructure

**Continuous Validation:**
- ✅ Daily: Verify certificate chain validity
- ✅ Weekly: Test certificate issuance/renewal
- ✅ Monthly: Audit log review
- ✅ Quarterly: Full PKI security audit
- ✅ Annually: Penetration test and red team exercise

### 10. Compliance and Documentation

**Required Documentation:**
- [ ] Certificate Policy (CP) document
- [ ] Certification Practice Statement (CPS)
- [ ] Root CA signing ceremony procedures
- [ ] Intermediary CA operational procedures
- [ ] Certificate issuance and validation workflows
- [ ] Incident response runbooks
- [ ] Key escrow and recovery procedures
- [ ] Disaster recovery plan
- [ ] Security audit results

**Compliance Frameworks:**
- NIST SP 800-57 (Key Management)
- NIST SP 800-52 (TLS Guidelines)
- RFC 5280 (X.509 Certificate Profile)
- CA/Browser Forum Baseline Requirements
- ISO/IEC 27001 (Information Security)

## Implementation Checklist

### Phase 1: Initial Setup
- [ ] Create offline root CA system
- [ ] Generate root CA key pair (HSM or encrypted storage)
- [ ] Create root CA certificate (20-year validity)
- [ ] Document root CA signing ceremony
- [ ] Calculate and record root CA pin
- [ ] Secure root CA in offline storage

### Phase 2: Intermediary CA
- [ ] Generate intermediary CA key pair
- [ ] Create CSR for intermediary
- [ ] Execute root CA signing ceremony
- [ ] Verify intermediary certificate chain
- [ ] Calculate intermediary CA pin
- [ ] Deploy intermediary CA to server
- [ ] Configure certificate issuance automation

### Phase 3: Client Integration
- [ ] Implement certificate issuance API
- [ ] Implement certificate validation logic
- [ ] Embed certificate pins in client
- [ ] Configure 1-hour certificate renewal
- [ ] Test end-to-end authentication flow

### Phase 4: Operations
- [ ] Configure audit logging
- [ ] Set up monitoring and alerting
- [ ] Document operational procedures
- [ ] Train operations team
- [ ] Schedule regular security audits

### Phase 5: Continuous Improvement
- [ ] Review security incidents quarterly
- [ ] Update procedures based on lessons learned
- [ ] Plan for post-quantum migration
- [ ] Conduct annual penetration tests
- [ ] Review and update documentation

## Quick Reference: Common Operations

### Calculate Certificate Pin
```bash
openssl x509 -in certificate.pem -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -hex
```

### Verify Certificate Chain
```bash
openssl verify -CAfile root-ca.pem \
    -untrusted intermediary-ca.pem \
    client-cert.pem
```

### Check Certificate Expiration
```bash
openssl x509 -in certificate.pem -noout -enddate
```

### Inspect Certificate Details
```bash
openssl x509 -in certificate.pem -noout -text
```

### Test Certificate with OpenSSL Server
```bash
# Server
openssl s_server -cert server.pem -key server.key -CAfile root-ca.pem \
    -verify 1 -Verify 1

# Client
openssl s_client -connect localhost:4433 \
    -cert client.pem -key client.key -CAfile root-ca.pem
```

## Contact and Support

**Security Incidents:**
- Email: security@example.com
- PGP Key: [fingerprint]
- Emergency Hotline: [phone]

**PKI Operations:**
- Email: pki-ops@example.com
- Ticket System: https://tickets.example.com
- On-Call Rotation: [pagerduty/oncall link]

## Appendix: Threat Model

**Threats Mitigated:**
- ✅ Man-in-the-Middle (MITM) attacks (certificate pinning)
- ✅ Certificate theft (1-hour TTL limits exposure)
- ✅ Rogue certificate issuance (offline root CA)
- ✅ Intermediary CA compromise (server-specific isolation)
- ✅ Certificate chain substitution (dual pinning)

**Residual Risks:**
- ⚠️ Root CA compromise (offline storage reduces risk)
- ⚠️ Pin update attacks (manual verification required)
- ⚠️ Client-side key theft (memory-only storage, 1h window)
- ⚠️ Quantum computer attacks (plan post-quantum migration)

**Future Enhancements:**
- Post-quantum cryptography (NIST PQC standards)
- Hardware security modules (HSMs) for all CAs
- Certificate Transparency (CT) logging
- Automated certificate lifecycle management
- Zero-trust architecture integration
