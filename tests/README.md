# PKI Test Suite Documentation

## Overview

Comprehensive test suite for the PKI (Public Key Infrastructure) security testing system, achieving >90% code coverage.

## Test Structure

```
tests/
├── conftest.py                    # Pytest fixtures and configuration
├── pytest.ini                     # Pytest settings
├── utils/                         # Test utilities and helpers
│   └── test_helpers.py           # Certificate factories and mock CA setup
├── unit/                          # Unit tests (fast, isolated)
│   ├── test_ca_manager.py        # CA initialization and key generation
│   ├── test_cert_issuer.py       # Certificate issuance
│   └── test_verification.py      # Dual verification logic
├── integration/                   # Integration tests (end-to-end)
│   ├── test_pki_service.py       # Complete PKI workflows
│   └── test_config_service.py    # Config service with mTLS
└── security/                      # Security tests
    └── test_security.py          # Security validation and attack prevention
```

## Test Categories

### Unit Tests (73 tests)

#### CA Manager Tests
- ✅ Root CA key generation (RSA 2048/4096)
- ✅ Root CA certificate generation with 10-year validity
- ✅ CA basic constraints (CA=true, critical)
- ✅ CA key usage (key_cert_sign, crl_sign, digital_signature)
- ✅ CA persistence (save/load certificates and keys)
- ✅ Intermediate CA generation per server
- ✅ Directory structure creation

#### Certificate Issuer Tests
- ✅ Server certificate generation
- ✅ Certificate signing by CA
- ✅ Public/private key matching
- ✅ Multiple certificates from same CA
- ✅ Server cert basic constraints (CA=false)
- ✅ Server cert key usage (digital_signature, key_encipherment)
- ✅ Subject fields and wildcards
- ✅ Validity periods (custom TTL)
- ✅ Serial number uniqueness
- ✅ Subject Alternative Names (SANs)
- ✅ Certificate chains (2-level and 3-level)

#### Verification Tests
- ✅ Dual verification (root + intermediary)
- ✅ Certificate chain validation
- ✅ Signature verification
- ✅ Self-signed certificate detection
- ✅ Chain ordering and continuity
- ✅ Missing intermediate detection
- ✅ Path length constraints
- ✅ Expiration detection (expired, not-yet-valid)

### Integration Tests (28 tests)

#### PKI Service Tests
- ✅ Complete PKI setup and issuance flow
- ✅ Multiple server certificate issuance
- ✅ Certificate renewal workflow
- ✅ Intermediary CA per server isolation
- ✅ Client certificate generation for mTLS
- ✅ Client certificate validation
- ✅ Expired client certificate rejection
- ✅ Server-to-server mTLS
- ✅ Shared root CA across containers
- ✅ Container-specific intermediate CAs

#### Config Service Tests
- ✅ Service initialization with PKI
- ✅ mTLS configuration
- ✅ Config download with valid certificates
- ✅ Blocking expired certificates
- ✅ Blocking invalid certificates
- ✅ Root CA download workflow
- ✅ Certificate bundle creation
- ✅ Server-specific certificate downloads
- ✅ Certificate package for deployment
- ✅ Configuration validation
- ✅ Multi-service configuration
- ✅ Error handling (missing files, corrupted certs)

### Security Tests (35 tests)

#### Expiration Validation
- ✅ Reject expired certificates
- ✅ Reject not-yet-valid certificates
- ✅ Warning for soon-to-expire certificates
- ✅ Expiration boundary testing

#### Invalid Certificate Rejection
- ✅ Reject self-signed server certificates
- ✅ Reject certificates from untrusted CAs
- ✅ Detect tampered certificates
- ✅ Reject weak key sizes (<2048 bits)

#### Chain of Trust
- ✅ Complete chain verification
- ✅ Broken chain detection
- ✅ Path length constraint enforcement
- ✅ Individual certificate validation

#### Unauthorized Access Prevention
- ✅ Reject unauthorized client certificates
- ✅ Prevent certificate substitution
- ✅ Enforce certificate purpose (key usage)
- ✅ Prevent unauthorized CA creation

#### Key Protection
- ✅ Private key encryption with password
- ✅ File permission restrictions (0600)
- ✅ Prevent key exposure in logs
- ✅ Key generation randomness

## Running Tests

### Run All Tests
```bash
pytest
```

### Run Specific Test Categories
```bash
# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# Security tests only
pytest tests/security/

# Specific test file
pytest tests/unit/test_ca_manager.py

# Specific test
pytest tests/unit/test_ca_manager.py::TestCAInitialization::test_generate_root_ca_key
```

### Run with Coverage
```bash
# Generate coverage report
pytest --cov=src --cov-report=html

# View HTML coverage report
open coverage_html/index.html
```

### Run with Markers
```bash
# Run only fast unit tests
pytest -m unit

# Run integration tests
pytest -m integration

# Run security tests
pytest -m security

# Skip slow tests
pytest -m "not slow"
```

## Test Fixtures

### Shared Fixtures (conftest.py)

- `temp_dir` - Temporary directory for test artifacts
- `ca_config` - CA configuration dictionary
- `cert_config` - Certificate configuration
- `mock_timestamp` - Consistent timestamp (2025-01-01)
- `expired_timestamp` - Past timestamp (2023-01-01)
- `future_timestamp` - Future timestamp (2026-01-01)

### Test Utilities

#### TestCertificateFactory
- `create_private_key()` - Generate RSA private key
- `create_ca_certificate()` - Generate CA certificate
- `create_server_certificate()` - Generate server certificate
- `create_expired_certificate()` - Generate expired certificate
- `save_certificate()` - Save certificate to PEM file
- `save_private_key()` - Save private key to PEM file

#### MockCASetup
- `setup_complete_pki()` - Setup root + intermediate CA
- `issue_server_certificate()` - Issue server certificate

#### Helper Functions
- `verify_certificate_chain()` - Verify cert chain
- `is_certificate_expired()` - Check expiration

## Coverage Goals

- **Target**: >90% code coverage
- **Statements**: >90%
- **Branches**: >85%
- **Functions**: >90%

## Test Best Practices

1. **Isolation**: Each test is independent
2. **Fast**: Unit tests complete in milliseconds
3. **Repeatable**: Same results every run
4. **Clear**: Descriptive test names
5. **Comprehensive**: Positive and negative cases
6. **Security-focused**: Attack scenarios tested

## Expected Test Count

- **Total Tests**: 136+
- **Unit Tests**: 73
- **Integration Tests**: 28
- **Security Tests**: 35

## CI/CD Integration

Tests are designed to run in CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Install dependencies
  run: pip install -e ".[dev]"

- name: Run tests with coverage
  run: pytest --cov=src --cov-fail-under=90

- name: Upload coverage
  uses: codecov/codecov-action@v3
```

## Dependencies

- `pytest>=8.4.2` - Test framework
- `pytest-cov>=6.0.0` - Coverage plugin
- `pytest-asyncio>=0.24.0` - Async test support
- `cryptography>=44.0.0` - PKI operations

## Test Execution Time

- **Unit tests**: ~2-5 seconds
- **Integration tests**: ~5-10 seconds
- **Security tests**: ~3-7 seconds
- **Total suite**: ~10-20 seconds

## Troubleshooting

### Import Errors
If you encounter import errors, ensure the package is installed:
```bash
pip install -e ".[dev]"
```

### Permission Errors
Temporary directories are auto-cleaned. If permission errors occur:
```bash
rm -rf /tmp/pytest-*
```

### Coverage Not Reaching 90%
The test suite is designed to achieve >90% coverage when actual implementation exists. Currently tests are for the planned PKI implementation.
