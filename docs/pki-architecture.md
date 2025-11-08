# PKI Architecture for Secure Console System

## Executive Summary

This document outlines a comprehensive Public Key Infrastructure (PKI) design for a secure console authentication system utilizing a three-tier certificate hierarchy: Root CA → Intermediary CA → Short-lived Client Certificates. This architecture provides robust security through certificate pinning, dual verification, and 1-hour certificate TTLs.

## 1. Certificate Hierarchy Design

### 1.1 Three-Tier Architecture

```
Root CA (Private, Offline)
    ├── Intermediary CA 1 (Server A)
    │   ├── Client Certificate 1 (1h TTL)
    │   ├── Client Certificate 2 (1h TTL)
    │   └── ...
    ├── Intermediary CA 2 (Server B)
    │   ├── Client Certificate 1 (1h TTL)
    │   └── ...
    └── Intermediary CA N (Server N)
```

**Key Characteristics:**
- **Root CA**: Long-lived (10-20 years), offline storage, used only for signing intermediary certificates
- **Intermediary CAs**: Medium-lived (2-5 years), one per server/service, online for certificate issuance
- **Client Certificates**: Short-lived (1 hour), issued on-demand for authentication

### 1.2 Certificate Properties

#### Root CA Certificate
```
Subject: CN=MyOrg Root CA, O=MyOrganization, C=US
Key Usage: Certificate Sign, CRL Sign
Basic Constraints: CA:TRUE, pathlen:1
Validity: 20 years
Key Size: RSA 4096 or EC P-384
```

#### Intermediary CA Certificate
```
Subject: CN=MyOrg Intermediary CA - ServerName, O=MyOrganization, C=US
Issuer: CN=MyOrg Root CA
Key Usage: Certificate Sign, CRL Sign
Basic Constraints: CA:TRUE, pathlen:0
Validity: 5 years
Key Size: RSA 2048 or EC P-256
Extended Key Usage: Server Authentication, Client Authentication
```

#### Client Certificate
```
Subject: CN=user@hostname, O=MyOrganization
Issuer: CN=MyOrg Intermediary CA - ServerName
Key Usage: Digital Signature, Key Encipherment
Extended Key Usage: Client Authentication
Validity: 1 hour
Key Size: RSA 2048 or EC P-256
Subject Alternative Name: email:user@example.com, DNS:hostname.local
```

## 2. Root CA Security Architecture

### 2.1 Storage and Protection

**Best Practices for Private CA Key Management:**

1. **Offline Storage** (Air-Gapped System)
   - Dedicated hardware security module (HSM) or offline computer
   - Physical security: locked safe or secure facility
   - No network connectivity during operation
   - Boot from read-only media for signing operations

2. **Key Material Protection**
   ```
   Root CA Private Key Storage Options (in order of security):

   Level 1 (Highest): Hardware Security Module (HSM)
   - FIPS 140-2 Level 3+ certified HSM
   - Tamper-resistant hardware
   - Key never exposed in plaintext

   Level 2: Encrypted File with Secure Enclave
   - AES-256 encrypted PKCS#8 format
   - Passphrase: 20+ characters, random
   - Stored on encrypted filesystem (LUKS, FileVault)
   - TPM/Secure Enclave for key derivation

   Level 3: Encrypted USB Token
   - YubiKey or similar FIDO2/PIV device
   - PIN-protected private key
   - Tamper-evident packaging
   ```

3. **Access Control**
   - Require 2-of-3 custodians for key access (Shamir Secret Sharing)
   - Audit log of all signing operations
   - Time-locked safe for emergency access
   - Documented signing ceremony with witnesses

### 2.2 Root CA Signing Ceremony

**Process for Intermediary Certificate Issuance:**

```bash
# 1. Prepare signing environment (offline system)
# 2. Verify integrity of root CA key material
# 3. Load certificate signing request (CSR) via USB
# 4. Verify CSR authenticity and authorization
# 5. Sign intermediary certificate
# 6. Export signed certificate
# 7. Verify certificate chain
# 8. Secure root CA key material
# 9. Document ceremony in audit log
```

### 2.3 File Structure for Root CA

```
/root-ca/
├── private/
│   ├── ca.key.pem              # Root CA private key (encrypted)
│   └── .key-access-log         # Access audit trail
├── certs/
│   ├── ca.cert.pem             # Root CA certificate
│   └── intermediates/
│       ├── server-a-ca.cert.pem
│       ├── server-b-ca.cert.pem
│       └── ...
├── crl/
│   └── root-ca.crl             # Certificate Revocation List
├── config/
│   ├── openssl-root-ca.cnf     # OpenSSL configuration
│   └── signing-policy.json     # Issuance policies
├── index.txt                   # Certificate database
├── serial                      # Serial number tracker
└── README.md                   # Emergency procedures
```

## 3. Intermediary CA Architecture

### 3.1 Server-Specific Intermediary Pattern

**Design Rationale:**
- Each server maintains its own intermediary CA
- Enables server-specific certificate revocation without affecting other servers
- Allows independent certificate policies per service
- Simplifies certificate pinning (clients pin both root + specific intermediary)

### 3.2 Intermediary CA Generation Workflow

```python
# Pseudocode for intermediary CA creation
def create_intermediary_ca(server_name):
    """
    Generate intermediary CA for specific server
    """
    # 1. Generate private key
    intermediary_key = generate_rsa_key(2048)

    # 2. Create Certificate Signing Request (CSR)
    csr = create_csr(
        common_name=f"Intermediary CA - {server_name}",
        organization="MyOrganization",
        key=intermediary_key
    )

    # 3. Transfer CSR to offline root CA (manual/USB)
    # 4. Root CA signs CSR (signing ceremony)
    # 5. Receive signed intermediary certificate

    # 6. Verify certificate chain
    verify_chain(intermediary_cert, root_ca_cert)

    # 7. Store on server
    store_certificate(
        server_name,
        intermediary_key,
        intermediary_cert
    )

    return intermediary_cert
```

### 3.3 Intermediary CA Security

**Storage Recommendations:**

```
/var/lib/console-auth/ca/
├── private/
│   └── intermediary-ca.key.pem  # Encrypted with server-specific key
├── certs/
│   ├── intermediary-ca.cert.pem
│   ├── root-ca.cert.pem         # For chain building
│   └── issued/
│       ├── client-001.cert.pem
│       ├── client-002.cert.pem
│       └── ...
├── crl/
│   └── intermediary-ca.crl
└── config/
    └── openssl-intermediary.cnf
```

**Protection Measures:**
- Encrypt intermediary private key with password + TPM-derived key
- Restrict file permissions: 0400 (owner read-only)
- Store in OS-level encrypted partition
- Implement rate limiting on certificate issuance
- Monitor for unauthorized access attempts

## 4. Short-Lived Certificate Pattern

### 4.1 1-Hour TTL Design

**Security Benefits:**
- Reduces window of compromise if certificate is stolen
- Eliminates need for complex revocation infrastructure for client certs
- Forces regular re-authentication (ensures user still authorized)
- Simplifies certificate lifecycle management

**Implementation Considerations:**

```python
def issue_client_certificate(user_id, hostname):
    """
    Issue 1-hour client certificate
    """
    # Generate ephemeral key pair
    client_key = generate_rsa_key(2048)

    # Create certificate
    cert = create_certificate(
        subject=f"CN={user_id}@{hostname}",
        issuer=intermediary_ca,
        public_key=client_key.public_key(),
        validity=timedelta(hours=1),
        serial=generate_serial(),
        extensions=[
            KeyUsage(digital_signature=True, key_encipherment=True),
            ExtendedKeyUsage(client_auth=True),
            SubjectAlternativeName(email=f"{user_id}@example.com"),
            # OCSP responder URL (optional for 1h certs)
        ]
    )

    # Sign with intermediary CA
    signed_cert = intermediary_ca.sign(cert)

    return signed_cert, client_key
```

### 4.2 Certificate Issuance Workflow

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ 1. Authentication Request (username/password)
       ▼
┌─────────────────────┐
│   Auth Service      │
│  (Intermediary CA)  │
└──────┬──────────────┘
       │ 2. Verify credentials
       │ 3. Generate key pair
       │ 4. Issue certificate (1h TTL)
       │ 5. Return cert + private key
       ▼
┌─────────────┐
│   Client    │
│ (stores in  │
│  memory)    │
└─────────────┘
```

### 4.3 Revocation Strategy for Short-Lived Certificates

**Simplified Approach:**
- **Primary**: Rely on short TTL (1 hour) - no formal revocation needed
- **Secondary**: Maintain in-memory blacklist for emergency revocation
- **Tertiary**: Certificate serial number tracking in database

```python
# In-memory revocation for emergency cases
revoked_serials = set()

def is_certificate_valid(cert):
    # Check 1: Not expired (1 hour TTL)
    if cert.not_valid_after < datetime.now(timezone.utc):
        return False

    # Check 2: Not in emergency revocation list
    if cert.serial_number in revoked_serials:
        return False

    # Check 3: Verify signatures
    if not verify_certificate_chain(cert):
        return False

    return True

def emergency_revoke(serial_number):
    """Revoke certificate immediately (rare emergency use)"""
    revoked_serials.add(serial_number)
    # Expires from memory after 1 hour automatically
```

## 5. Dual Verification Architecture

### 5.1 Certificate Pinning Strategy

**Two-Level Pinning:**

```python
class CertificateValidator:
    def __init__(self, root_ca_pin, intermediary_ca_pin):
        """
        Initialize validator with pinned certificates

        Args:
            root_ca_pin: SHA256 hash of root CA public key
            intermediary_ca_pin: SHA256 hash of intermediary CA public key
        """
        self.root_ca_pin = root_ca_pin
        self.intermediary_ca_pin = intermediary_ca_pin

    def validate_client_certificate(self, client_cert, cert_chain):
        """
        Validate client certificate against pinned CAs

        Verification Steps:
        1. Verify certificate chain completeness
        2. Verify client cert signed by pinned intermediary
        3. Verify intermediary signed by pinned root
        4. Check certificate validity period
        5. Verify key usage extensions
        """
        # Extract certificates from chain
        client = cert_chain[0]
        intermediary = cert_chain[1]
        root = cert_chain[2]

        # Step 1: Pin verification
        if not self._verify_pin(intermediary, self.intermediary_ca_pin):
            raise ValidationError("Intermediary CA pin mismatch")

        if not self._verify_pin(root, self.root_ca_pin):
            raise ValidationError("Root CA pin mismatch")

        # Step 2: Signature verification
        if not self._verify_signature(client, intermediary):
            raise ValidationError("Client cert not signed by intermediary")

        if not self._verify_signature(intermediary, root):
            raise ValidationError("Intermediary not signed by root")

        # Step 3: Validity checks
        self._check_validity_period(client)
        self._check_key_usage(client)

        return True

    def _verify_pin(self, cert, expected_pin):
        """Verify certificate public key matches pin"""
        public_key_der = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        actual_pin = hashlib.sha256(public_key_der).hexdigest()
        return actual_pin == expected_pin
```

### 5.2 Pin Storage and Distribution

**Client-Side Pin Configuration:**

```json
{
  "security": {
    "certificate_pins": {
      "root_ca": {
        "algorithm": "sha256",
        "pin": "a1b2c3d4e5f6...7890",
        "backup_pins": [
          "backup_pin_1",
          "backup_pin_2"
        ]
      },
      "intermediary_ca": {
        "server_a": {
          "algorithm": "sha256",
          "pin": "1234567890ab...",
          "valid_until": "2030-01-01T00:00:00Z"
        }
      }
    },
    "pin_update_policy": {
      "auto_update": false,
      "require_manual_verification": true
    }
  }
}
```

**Pin Distribution Methods:**
1. **Initial Setup**: Embedded in application binary (code signing verified)
2. **Updates**: Manual administrator verification required
3. **Backup Pins**: Include 2-3 backup root CA pins for rotation

## 6. Certificate Chain Validation

### 6.1 Complete Chain of Trust

```
┌─────────────────────────────────────────────────────┐
│                  Certificate Chain                   │
└─────────────────────────────────────────────────────┘

[Client Certificate]
    Subject: CN=alice@workstation, O=MyOrg
    Issuer: CN=MyOrg Intermediary CA - ServerA
    Validity: 2025-11-08 01:00:00 → 02:00:00 (1h)
    Serial: 0x1234567890ABCDEF
    Public Key: RSA 2048
    Signature Algorithm: SHA256-RSA
    Extensions:
        - Key Usage: Digital Signature, Key Encipherment
        - Extended Key Usage: Client Authentication
        - Subject Alt Name: email:alice@example.com

    Signed by: [Intermediary CA]
           ↓

[Intermediary CA Certificate]
    Subject: CN=MyOrg Intermediary CA - ServerA, O=MyOrg
    Issuer: CN=MyOrg Root CA
    Validity: 2025-01-01 → 2030-01-01 (5y)
    Serial: 0xABCDEF1234567890
    Public Key: RSA 2048
    Signature Algorithm: SHA256-RSA
    Extensions:
        - Key Usage: Certificate Sign, CRL Sign
        - Basic Constraints: CA:TRUE, pathlen:0
        - Extended Key Usage: Server Auth, Client Auth

    Signed by: [Root CA]
           ↓

[Root CA Certificate]
    Subject: CN=MyOrg Root CA, O=MyOrg, C=US
    Issuer: CN=MyOrg Root CA (self-signed)
    Validity: 2025-01-01 → 2045-01-01 (20y)
    Serial: 0x1
    Public Key: RSA 4096
    Signature Algorithm: SHA256-RSA
    Extensions:
        - Key Usage: Certificate Sign, CRL Sign
        - Basic Constraints: CA:TRUE, pathlen:1

    Self-signed (trust anchor)
```

### 6.2 Validation Algorithm

```python
def validate_certificate_chain(client_cert, intermediary_cert, root_cert):
    """
    Comprehensive certificate chain validation
    """
    errors = []

    # 1. CHAIN COMPLETENESS
    if client_cert.issuer != intermediary_cert.subject:
        errors.append("Client cert issuer doesn't match intermediary subject")

    if intermediary_cert.issuer != root_cert.subject:
        errors.append("Intermediary issuer doesn't match root subject")

    # 2. SIGNATURE VERIFICATION
    try:
        # Verify client cert signed by intermediary
        intermediary_cert.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm
        )
    except InvalidSignature:
        errors.append("Client certificate signature invalid")

    try:
        # Verify intermediary signed by root
        root_cert.public_key().verify(
            intermediary_cert.signature,
            intermediary_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            intermediary_cert.signature_hash_algorithm
        )
    except InvalidSignature:
        errors.append("Intermediary certificate signature invalid")

    # 3. VALIDITY PERIOD
    now = datetime.now(timezone.utc)

    if not (client_cert.not_valid_before <= now <= client_cert.not_valid_after):
        errors.append(f"Client cert expired or not yet valid")

    if not (intermediary_cert.not_valid_before <= now <= intermediary_cert.not_valid_after):
        errors.append(f"Intermediary cert expired or not yet valid")

    if not (root_cert.not_valid_before <= now <= root_cert.not_valid_after):
        errors.append(f"Root cert expired or not yet valid")

    # 4. BASIC CONSTRAINTS
    if not is_ca_certificate(intermediary_cert):
        errors.append("Intermediary is not a CA certificate")

    if not is_ca_certificate(root_cert):
        errors.append("Root is not a CA certificate")

    # 5. PATH LENGTH CONSTRAINT
    root_pathlen = get_path_length_constraint(root_cert)
    if root_pathlen is not None and root_pathlen < 1:
        errors.append("Root CA path length constraint violated")

    intermediary_pathlen = get_path_length_constraint(intermediary_cert)
    if intermediary_pathlen is not None and intermediary_pathlen < 0:
        errors.append("Intermediary CA path length constraint violated")

    # 6. KEY USAGE
    if not has_key_usage(client_cert, KeyUsage.digital_signature):
        errors.append("Client cert missing digital signature key usage")

    if not has_extended_key_usage(client_cert, ExtendedKeyUsage.client_auth):
        errors.append("Client cert missing client auth extended key usage")

    # 7. REVOCATION CHECK (for intermediary only)
    if is_revoked(intermediary_cert):
        errors.append("Intermediary certificate has been revoked")

    if errors:
        raise CertificateValidationError(errors)

    return True
```

### 6.3 Certificate Pinning Implementation

```python
class PinnedCertificateValidator:
    """
    Validates certificates against pinned public keys
    """

    def __init__(self, config_path):
        with open(config_path) as f:
            config = json.load(f)

        self.root_pin = config['security']['certificate_pins']['root_ca']['pin']
        self.intermediary_pins = config['security']['certificate_pins']['intermediary_ca']

    def validate(self, client_cert_pem, server_name):
        """
        Validate client certificate with dual pinning
        """
        # Parse certificate chain
        certs = parse_pem_chain(client_cert_pem)
        client_cert = certs[0]
        intermediary_cert = certs[1]
        root_cert = certs[2]

        # Verify root CA pin
        root_pin = self._calculate_pin(root_cert)
        if root_pin != self.root_pin:
            raise PinValidationError("Root CA pin mismatch - possible MITM attack")

        # Verify intermediary CA pin for specific server
        expected_intermediary_pin = self.intermediary_pins[server_name]['pin']
        intermediary_pin = self._calculate_pin(intermediary_cert)
        if intermediary_pin != expected_intermediary_pin:
            raise PinValidationError(f"Intermediary CA pin mismatch for {server_name}")

        # Perform standard certificate chain validation
        validate_certificate_chain(client_cert, intermediary_cert, root_cert)

        return True

    def _calculate_pin(self, cert):
        """Calculate SHA256 pin of certificate public key"""
        public_key_der = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(public_key_der).hexdigest()
```

## 7. File Structure and Organization

### 7.1 Complete Directory Structure

```
/var/lib/console-auth/
├── root-ca/                          # Root CA (offline backup)
│   ├── private/
│   │   ├── ca.key.pem               # Encrypted root private key
│   │   └── .access-log
│   ├── certs/
│   │   ├── ca.cert.pem              # Root CA certificate
│   │   └── chain/
│   │       └── full-chain.pem
│   └── config/
│       └── openssl.cnf
│
├── intermediary-ca/                  # Server-specific intermediary
│   ├── private/
│   │   └── intermediary.key.pem     # Encrypted intermediary key
│   ├── certs/
│   │   ├── intermediary.cert.pem
│   │   ├── root.cert.pem            # Copy for chain building
│   │   ├── chain.pem                # Full chain
│   │   └── issued/                  # Issued client certificates
│   │       ├── 2025-11-08/
│   │       │   ├── client-001.cert.pem
│   │       │   └── client-002.cert.pem
│   │       └── index.txt
│   ├── crl/
│   │   └── intermediary.crl
│   └── config/
│       └── openssl.cnf
│
├── client/                           # Client-side files
│   ├── pins/
│   │   └── certificate-pins.json    # Pinned public keys
│   ├── certs/
│   │   ├── client.cert.pem          # Current client certificate
│   │   └── client.key.pem           # Client private key
│   └── trusted/
│       ├── root-ca.cert.pem         # Trusted root CA
│       └── intermediary-ca.cert.pem # Trusted intermediary
│
└── logs/
    ├── issuance.log                 # Certificate issuance audit
    ├── validation.log               # Validation attempts
    └── revocation.log               # Revocation events
```

### 7.2 Configuration Files

**OpenSSL Root CA Configuration (`root-ca/config/openssl.cnf`):**

```ini
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = /var/lib/console-auth/root-ca
certs            = $dir/certs
crl_dir          = $dir/crl
new_certs_dir    = $dir/certs/intermediates
database         = $dir/index.txt
serial           = $dir/serial
RANDFILE         = $dir/private/.rand
private_key      = $dir/private/ca.key.pem
certificate      = $dir/certs/ca.cert.pem
crlnumber        = $dir/crlnumber
crl              = $dir/crl/ca.crl.pem
crl_extensions   = crl_ext
default_crl_days = 30
default_md       = sha256
name_opt         = ca_default
cert_opt         = ca_default
default_days     = 1825
preserve         = no
policy           = policy_strict

[ policy_strict ]
countryName            = match
stateOrProvinceName    = optional
organizationName       = match
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
string_mask        = utf8only
default_md         = sha256
x509_extensions    = v3_ca

[ req_distinguished_name ]
countryName                    = Country Name (2 letter code)
stateOrProvinceName            = State or Province Name
localityName                   = Locality Name
0.organizationName             = Organization Name
organizationalUnitName         = Organizational Unit Name
commonName                     = Common Name
emailAddress                   = Email Address

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:1
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign
extendedKeyUsage       = serverAuth, clientAuth
```

**OpenSSL Intermediary CA Configuration (`intermediary-ca/config/openssl.cnf`):**

```ini
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = /var/lib/console-auth/intermediary-ca
certs            = $dir/certs
crl_dir          = $dir/crl
new_certs_dir    = $dir/certs/issued
database         = $dir/index.txt
serial           = $dir/serial
RANDFILE         = $dir/private/.rand
private_key      = $dir/private/intermediary.key.pem
certificate      = $dir/certs/intermediary.cert.pem
crlnumber        = $dir/crlnumber
crl              = $dir/crl/intermediary.crl.pem
crl_extensions   = crl_ext
default_crl_days = 30
default_md       = sha256
name_opt         = ca_default
cert_opt         = ca_default
default_days     = 0.0417  # 1 hour in days
preserve         = no
policy           = policy_loose

[ policy_loose ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
string_mask        = utf8only
default_md         = sha256

[ req_distinguished_name ]
commonName                     = Common Name
emailAddress                   = Email Address

[ usr_cert ]
basicConstraints       = CA:FALSE
nsCertType             = client, email
nsComment              = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth, emailProtection

[ client_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = critical, clientAuth
# Add OCSP responder if needed
# authorityInfoAccess    = OCSP;URI:http://ocsp.example.com
```

## 8. Security Best Practices Summary

### 8.1 Key Management

| Component | Key Size | Storage | Rotation |
|-----------|----------|---------|----------|
| Root CA | RSA 4096 / EC P-384 | HSM or encrypted offline | 10-20 years |
| Intermediary CA | RSA 2048 / EC P-256 | Encrypted file + TPM | 2-5 years |
| Client Cert | RSA 2048 / EC P-256 | Memory only | 1 hour |

### 8.2 Certificate Policies

1. **Root CA**
   - Never connect to network
   - Require multi-party authorization for signing
   - Maintain offline backups in geographically separate locations
   - Document all signing operations

2. **Intermediary CA**
   - One per server/service
   - Encrypt private key with strong passphrase + hardware-backed key
   - Rate limit certificate issuance (prevent DoS)
   - Monitor for anomalous issuance patterns

3. **Client Certificates**
   - 1-hour validity period (short-lived)
   - Never persist private key to disk
   - Implement certificate serial number tracking
   - Emergency revocation blacklist in memory

### 8.3 Operational Security

**Certificate Issuance:**
- Authenticate user before issuing certificate
- Log all certificate issuances with timestamp, user, IP
- Implement rate limiting (e.g., max 10 certificates per user per hour)
- Monitor for suspicious patterns

**Certificate Validation:**
- Always verify complete chain (client → intermediary → root)
- Implement certificate pinning for both root and intermediary
- Check validity periods strictly
- Verify key usage and extended key usage extensions

**Incident Response:**
- Emergency intermediary revocation procedure
- Root CA backup recovery plan
- Certificate serial number blacklist mechanism
- Automated alerting for validation failures

### 8.4 Cryptographic Recommendations

**Algorithms (2025 Standards):**
- **Signature**: RSA-PSS with SHA-256 or ECDSA with P-256/P-384
- **Encryption**: AES-256-GCM or ChaCha20-Poly1305
- **Key Exchange**: ECDH with P-256 or X25519
- **Avoid**: SHA-1, MD5, RSA < 2048, DES, 3DES

**Future-Proofing:**
- Plan for post-quantum migration (NIST PQC standards)
- Use hybrid classical + post-quantum signatures
- Monitor NIST guidance on quantum-resistant algorithms

## 9. Implementation Workflows

### 9.1 Initial PKI Setup

```bash
#!/bin/bash
# Initialize PKI infrastructure

# 1. Create directory structure
mkdir -p /var/lib/console-auth/{root-ca,intermediary-ca,client}/{private,certs,crl,config}
chmod 700 /var/lib/console-auth/*/private

# 2. Generate root CA (offline system)
cd /var/lib/console-auth/root-ca
openssl genrsa -aes256 -out private/ca.key.pem 4096
chmod 400 private/ca.key.pem

openssl req -config config/openssl.cnf \
    -key private/ca.key.pem \
    -new -x509 -days 7300 -sha256 -extensions v3_ca \
    -out certs/ca.cert.pem

# 3. Generate intermediary CA CSR (online server)
cd /var/lib/console-auth/intermediary-ca
openssl genrsa -aes256 -out private/intermediary.key.pem 2048
chmod 400 private/intermediary.key.pem

openssl req -config config/openssl.cnf \
    -key private/intermediary.key.pem \
    -new -sha256 -out csr/intermediary.csr.pem

# 4. Sign intermediary CSR with root CA (offline system)
cd /var/lib/console-auth/root-ca
openssl ca -config config/openssl.cnf \
    -extensions v3_intermediate_ca -days 1825 -notext -md sha256 \
    -in ../intermediary-ca/csr/intermediary.csr.pem \
    -out certs/intermediates/intermediary.cert.pem

# 5. Create certificate chain
cat intermediary-ca/certs/intermediary.cert.pem \
    root-ca/certs/ca.cert.pem > intermediary-ca/certs/chain.pem

# 6. Calculate certificate pins
openssl x509 -in root-ca/certs/ca.cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -binary | \
    openssl enc -base64

openssl x509 -in intermediary-ca/certs/intermediary.cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -binary | \
    openssl enc -base64
```

### 9.2 Client Certificate Issuance Workflow

```python
def issue_client_certificate(user_id, hostname, intermediary_ca_key, intermediary_ca_cert):
    """
    Issue 1-hour client certificate

    Args:
        user_id: User identifier (e.g., "alice")
        hostname: Client hostname
        intermediary_ca_key: Intermediary CA private key
        intermediary_ca_cert: Intermediary CA certificate

    Returns:
        tuple: (client_certificate_pem, client_private_key_pem)
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone
    import secrets

    # 1. Generate client private key
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 2. Build certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{user_id}@{hostname}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrganization"),
    ])

    # 3. Create certificate
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(intermediary_ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(secrets.randbits(128))
        .not_valid_before(now)
        .not_valid_after(now + timedelta(hours=1))  # 1-hour TTL
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.RFC822Name(f"{user_id}@example.com"),
                x509.DNSName(f"{hostname}.local"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                intermediary_ca_cert.public_key()
            ),
            critical=False,
        )
        .sign(intermediary_ca_key, hashes.SHA256())
    )

    # 4. Serialize to PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No password for short-lived
    )

    # 5. Log issuance
    log_certificate_issuance(
        serial=cert.serial_number,
        subject=subject,
        issued_at=now,
        expires_at=now + timedelta(hours=1),
        user_id=user_id,
        hostname=hostname
    )

    return cert_pem, key_pem
```

### 9.3 Certificate Validation Workflow

```python
def validate_client_authentication(
    client_cert_chain_pem,
    root_ca_pin,
    intermediary_ca_pin,
    server_name
):
    """
    Validate client certificate for authentication

    Args:
        client_cert_chain_pem: PEM-encoded certificate chain
        root_ca_pin: Expected SHA256 pin of root CA public key
        intermediary_ca_pin: Expected SHA256 pin of intermediary CA
        server_name: Server name for intermediary pin lookup

    Returns:
        dict: Validation result with user identity

    Raises:
        CertificateValidationError: If validation fails
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from datetime import datetime, timezone
    import hashlib

    # 1. Parse certificate chain
    certs = []
    for cert_pem in client_cert_chain_pem.split(b'-----END CERTIFICATE-----'):
        if b'-----BEGIN CERTIFICATE-----' in cert_pem:
            cert = x509.load_pem_x509_certificate(
                cert_pem + b'-----END CERTIFICATE-----'
            )
            certs.append(cert)

    if len(certs) != 3:
        raise CertificateValidationError(
            f"Expected 3 certificates in chain, got {len(certs)}"
        )

    client_cert, intermediary_cert, root_cert = certs

    # 2. Verify certificate pins
    def calculate_pin(cert):
        public_key_der = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(public_key_der).hexdigest()

    if calculate_pin(root_cert) != root_ca_pin:
        raise CertificateValidationError("Root CA pin mismatch - possible MITM")

    if calculate_pin(intermediary_cert) != intermediary_ca_pin:
        raise CertificateValidationError(
            f"Intermediary CA pin mismatch for {server_name}"
        )

    # 3. Verify certificate chain signatures
    try:
        # Verify client cert signed by intermediary
        intermediary_cert.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise CertificateValidationError(f"Client cert signature invalid: {e}")

    try:
        # Verify intermediary signed by root
        root_cert.public_key().verify(
            intermediary_cert.signature,
            intermediary_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            intermediary_cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise CertificateValidationError(f"Intermediary signature invalid: {e}")

    # 4. Verify validity periods
    now = datetime.now(timezone.utc)

    if not (client_cert.not_valid_before_utc <= now <= client_cert.not_valid_after_utc):
        raise CertificateValidationError("Client certificate expired or not yet valid")

    if not (intermediary_cert.not_valid_before_utc <= now <= intermediary_cert.not_valid_after_utc):
        raise CertificateValidationError("Intermediary certificate expired")

    if not (root_cert.not_valid_before_utc <= now <= root_cert.not_valid_after_utc):
        raise CertificateValidationError("Root certificate expired")

    # 5. Verify certificate extensions
    try:
        key_usage = client_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        ).value
        if not key_usage.digital_signature:
            raise CertificateValidationError("Client cert missing digital signature usage")
    except x509.ExtensionNotFound:
        raise CertificateValidationError("Client cert missing key usage extension")

    try:
        ext_key_usage = client_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        from cryptography.x509.oid import ExtendedKeyUsageOID
        if ExtendedKeyUsageOID.CLIENT_AUTH not in ext_key_usage:
            raise CertificateValidationError("Client cert missing client auth usage")
    except x509.ExtensionNotFound:
        raise CertificateValidationError("Client cert missing extended key usage")

    # 6. Extract user identity from certificate
    common_name = client_cert.subject.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME
    )[0].value

    # Parse user@hostname format
    if '@' in common_name:
        user_id, hostname = common_name.split('@', 1)
    else:
        user_id = common_name
        hostname = None

    return {
        'valid': True,
        'user_id': user_id,
        'hostname': hostname,
        'serial_number': client_cert.serial_number,
        'expires_at': client_cert.not_valid_after_utc.isoformat(),
    }
```

## 10. Monitoring and Auditing

### 10.1 Audit Logging

**Required Audit Events:**

```python
# Certificate lifecycle events
AUDIT_EVENTS = {
    'CA_INITIALIZED': 'Certificate Authority initialized',
    'CERT_ISSUED': 'Client certificate issued',
    'CERT_RENEWED': 'Client certificate renewed',
    'CERT_REVOKED': 'Certificate revoked',
    'CERT_VALIDATED': 'Certificate validation successful',
    'CERT_VALIDATION_FAILED': 'Certificate validation failed',
    'PIN_MISMATCH': 'Certificate pin mismatch detected',
    'CHAIN_INVALID': 'Certificate chain validation failed',
    'CERT_EXPIRED': 'Expired certificate presented',
}

def audit_log(event_type, details):
    """
    Log security-relevant events

    Args:
        event_type: One of AUDIT_EVENTS
        details: dict with event-specific information
    """
    log_entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event': event_type,
        'description': AUDIT_EVENTS[event_type],
        **details
    }

    # Write to tamper-evident log
    with open('/var/log/console-auth/audit.log', 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

    # Send to SIEM if critical event
    if event_type in ['PIN_MISMATCH', 'CHAIN_INVALID', 'CERT_REVOKED']:
        send_to_siem(log_entry)
```

### 10.2 Monitoring Metrics

**Key Performance Indicators:**

- Certificate issuance rate (per minute/hour)
- Certificate validation success rate
- Certificate validation latency (p50, p95, p99)
- Pin mismatch rate (should be near zero)
- Certificate expiration warnings
- Root CA signing operations (should be rare)

### 10.3 Alerting Rules

```yaml
alerts:
  - name: certificate_pin_mismatch
    condition: pin_mismatch_count > 0
    severity: critical
    action: immediate_investigation
    description: Possible MITM attack detected

  - name: high_validation_failure_rate
    condition: validation_failure_rate > 5%
    severity: warning
    action: investigate_within_1hour

  - name: intermediary_cert_expiring
    condition: days_until_expiry < 30
    severity: warning
    action: plan_renewal

  - name: root_cert_expiring
    condition: days_until_expiry < 180
    severity: critical
    action: immediate_renewal_planning
```

## 11. Conclusion

This PKI architecture provides defense-in-depth security through:

1. **Three-tier certificate hierarchy** with offline root CA
2. **Server-specific intermediary CAs** for isolation and granular control
3. **Short-lived 1-hour client certificates** eliminating complex revocation
4. **Dual certificate pinning** preventing MITM attacks
5. **Comprehensive chain validation** ensuring cryptographic integrity

The architecture balances security, usability, and operational complexity, providing a robust foundation for secure console authentication.

## Appendix A: Quick Reference Commands

```bash
# Generate root CA
openssl genrsa -aes256 -out root-ca.key 4096
openssl req -x509 -new -nodes -key root-ca.key -sha256 -days 7300 -out root-ca.crt

# Generate intermediary CA CSR
openssl genrsa -out intermediary-ca.key 2048
openssl req -new -key intermediary-ca.key -out intermediary-ca.csr

# Sign intermediary with root
openssl x509 -req -in intermediary-ca.csr -CA root-ca.crt -CAkey root-ca.key \
    -CAcreateserial -out intermediary-ca.crt -days 1825 -sha256 \
    -extfile <(printf "basicConstraints=CA:TRUE,pathlen:0\nkeyUsage=keyCertSign,cRLSign")

# Issue client certificate (1 hour)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA intermediary-ca.crt -CAkey intermediary-ca.key \
    -CAcreateserial -out client.crt -days 0.0417 -sha256 \
    -extfile <(printf "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth")

# Calculate certificate pin
openssl x509 -in cert.crt -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -hex

# Verify certificate chain
openssl verify -CAfile root-ca.crt -untrusted intermediary-ca.crt client.crt
```

## Appendix B: Python Library Recommendations

**Recommended Libraries:**
- **cryptography**: Modern, secure cryptographic primitives (recommended)
- **PyCA**: Certificate authority toolkit
- **certifi**: Trusted root certificates bundle
- **pyOpenSSL**: Legacy interface (use cryptography instead)

**Installation:**
```bash
pip install cryptography>=42.0.0
```

## Appendix C: Security Considerations Checklist

- [ ] Root CA private key stored offline with encryption
- [ ] Multi-party authorization for root CA operations
- [ ] Intermediary CA keys encrypted with hardware-backed protection
- [ ] Certificate pins calculated and distributed securely
- [ ] Client certificates limited to 1-hour validity
- [ ] Certificate chain validation implemented correctly
- [ ] Audit logging enabled for all PKI operations
- [ ] Monitoring and alerting configured
- [ ] Incident response procedures documented
- [ ] Regular security audits scheduled
- [ ] Key rotation procedures documented
- [ ] Backup and recovery procedures tested
- [ ] Post-quantum migration plan developed
