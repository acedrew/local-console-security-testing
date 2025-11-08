"""Test helper utilities for PKI operations."""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class TestCertificateFactory:
    """Factory for creating test certificates and keys."""

    @staticmethod
    def create_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
        """Create a test private key."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

    @staticmethod
    def create_ca_certificate(
        subject_name: str = "Test CA",
        validity_days: int = 3650,
        key: Optional[rsa.RSAPrivateKey] = None,
        issuer_cert: Optional[x509.Certificate] = None,
        issuer_key: Optional[rsa.RSAPrivateKey] = None,
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Create a test CA certificate."""
        if key is None:
            key = TestCertificateFactory.create_private_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "TestState"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "TestCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])

        # Self-signed or signed by issuer
        issuer = subject if issuer_cert is None else issuer_cert.subject
        signing_key = key if issuer_key is None else issuer_key

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(signing_key, hashes.SHA256(), default_backend())
        )

        return cert, key

    @staticmethod
    def create_server_certificate(
        common_name: str,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
        validity_days: int = 365,
        san_dns: Optional[list[str]] = None,
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Create a test server certificate."""
        key = TestCertificateFactory.create_private_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )

        # Add Subject Alternative Names if provided
        if san_dns:
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(name) for name in san_dns]
                ),
                critical=False,
            )

        cert = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())

        return cert, key

    @staticmethod
    def save_certificate(cert: x509.Certificate, path: Path) -> None:
        """Save certificate to PEM file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def save_private_key(key: rsa.RSAPrivateKey, path: Path, password: Optional[bytes] = None) -> None:
        """Save private key to PEM file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        with open(path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=encryption,
                )
            )

    @staticmethod
    def create_expired_certificate(
        common_name: str,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey,
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Create an expired certificate for testing."""
        key = TestCertificateFactory.create_private_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # Create certificate that expired yesterday
        not_before = datetime.utcnow() - timedelta(days=30)
        not_after = datetime.utcnow() - timedelta(days=1)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        return cert, key


class MockCASetup:
    """Mock CA setup for testing."""

    def __init__(self, base_path: Path):
        """Initialize mock CA setup."""
        self.base_path = base_path
        self.root_cert = None
        self.root_key = None
        self.intermediate_cert = None
        self.intermediate_key = None

    def setup_complete_pki(self) -> None:
        """Setup complete PKI infrastructure."""
        # Create root CA
        self.root_cert, self.root_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Test Root CA",
            validity_days=3650,
        )

        # Create intermediate CA
        self.intermediate_cert, self.intermediate_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Test Intermediate CA",
            validity_days=1825,
            issuer_cert=self.root_cert,
            issuer_key=self.root_key,
        )

        # Save certificates
        ca_dir = self.base_path / "ca"
        TestCertificateFactory.save_certificate(
            self.root_cert, ca_dir / "root_ca.crt"
        )
        TestCertificateFactory.save_private_key(
            self.root_key, ca_dir / "root_ca.key"
        )
        TestCertificateFactory.save_certificate(
            self.intermediate_cert, ca_dir / "intermediate_ca.crt"
        )
        TestCertificateFactory.save_private_key(
            self.intermediate_key, ca_dir / "intermediate_ca.key"
        )

    def issue_server_certificate(
        self, server_name: str, san_dns: Optional[list[str]] = None
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Issue a server certificate."""
        if self.intermediate_cert is None or self.intermediate_key is None:
            raise ValueError("PKI not initialized. Call setup_complete_pki() first.")

        cert, key = TestCertificateFactory.create_server_certificate(
            common_name=server_name,
            ca_cert=self.intermediate_cert,
            ca_key=self.intermediate_key,
            san_dns=san_dns,
        )

        # Save certificate
        server_dir = self.base_path / "servers" / server_name
        TestCertificateFactory.save_certificate(cert, server_dir / "server.crt")
        TestCertificateFactory.save_private_key(key, server_dir / "server.key")

        return cert, key


def verify_certificate_chain(
    cert: x509.Certificate,
    intermediate_cert: x509.Certificate,
    root_cert: x509.Certificate,
) -> bool:
    """Verify a certificate chain."""
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend

        # Verify server cert is signed by intermediate
        intermediate_public_key = intermediate_cert.public_key()
        intermediate_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

        # Verify intermediate cert is signed by root
        root_public_key = root_cert.public_key()
        root_public_key.verify(
            intermediate_cert.signature,
            intermediate_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            intermediate_cert.signature_hash_algorithm,
        )

        return True
    except Exception:
        return False


def is_certificate_expired(cert: x509.Certificate, check_time: Optional[datetime] = None) -> bool:
    """Check if a certificate is expired."""
    now = check_time or datetime.utcnow()
    return now < cert.not_valid_before or now > cert.not_valid_after


# Test these helpers
def test_create_private_key():
    """Test private key creation."""
    key = TestCertificateFactory.create_private_key()
    assert key is not None
    assert key.key_size == 2048


def test_create_ca_certificate():
    """Test CA certificate creation."""
    cert, key = TestCertificateFactory.create_ca_certificate()
    assert cert is not None
    assert key is not None

    # Verify it's a CA certificate
    basic_constraints = cert.extensions.get_extension_for_oid(
        ExtensionOID.BASIC_CONSTRAINTS
    )
    assert basic_constraints.value.ca is True


def test_create_server_certificate():
    """Test server certificate creation."""
    ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
    server_cert, server_key = TestCertificateFactory.create_server_certificate(
        common_name="test.example.com",
        ca_cert=ca_cert,
        ca_key=ca_key,
    )

    assert server_cert is not None
    assert server_key is not None

    # Verify it's not a CA certificate
    basic_constraints = server_cert.extensions.get_extension_for_oid(
        ExtensionOID.BASIC_CONSTRAINTS
    )
    assert basic_constraints.value.ca is False


def test_expired_certificate():
    """Test expired certificate creation."""
    ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
    expired_cert, _ = TestCertificateFactory.create_expired_certificate(
        common_name="expired.example.com",
        ca_cert=ca_cert,
        ca_key=ca_key,
    )

    assert is_certificate_expired(expired_cert)


def test_mock_ca_setup(temp_dir):
    """Test mock CA setup."""
    mock_ca = MockCASetup(temp_dir)
    mock_ca.setup_complete_pki()

    assert mock_ca.root_cert is not None
    assert mock_ca.intermediate_cert is not None
    assert (temp_dir / "ca" / "root_ca.crt").exists()
    assert (temp_dir / "ca" / "intermediate_ca.crt").exists()


def test_certificate_chain_verification(temp_dir):
    """Test certificate chain verification."""
    mock_ca = MockCASetup(temp_dir)
    mock_ca.setup_complete_pki()

    server_cert, _ = mock_ca.issue_server_certificate("test.example.com")

    is_valid = verify_certificate_chain(
        server_cert,
        mock_ca.intermediate_cert,
        mock_ca.root_cert,
    )
    assert is_valid is True
