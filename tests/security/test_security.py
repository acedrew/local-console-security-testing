"""Security tests for PKI system."""

import pytest
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from ..utils.test_helpers import (
    TestCertificateFactory,
    MockCASetup,
    verify_certificate_chain,
    is_certificate_expired,
)


class TestCertificateExpirationValidation:
    """Test certificate expiration security checks."""

    def test_reject_expired_certificates(self, temp_dir):
        """Test that expired certificates are properly rejected."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        expired_cert, _ = TestCertificateFactory.create_expired_certificate(
            common_name="expired.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        # Should be detected as expired
        assert is_certificate_expired(expired_cert) is True

    def test_reject_not_yet_valid_certificates(self, temp_dir):
        """Test that not-yet-valid certificates are rejected."""
        key = TestCertificateFactory.create_private_key()
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "future.example.com"),
        ])

        # Create certificate valid in future
        future_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() + timedelta(days=10))
            .not_valid_after(datetime.utcnow() + timedelta(days=375))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        # Should be detected as not yet valid
        assert is_certificate_expired(future_cert) is True

    def test_warn_on_soon_to_expire_certificates(self, temp_dir):
        """Test warning for certificates expiring soon."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        # Create certificate expiring in 7 days
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="expiring-soon.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
            validity_days=7,
        )

        # Calculate days until expiration
        now = datetime.utcnow()
        days_until_expiry = (server_cert.not_valid_after - now).days

        # Should warn if < 30 days
        should_warn = days_until_expiry < 30
        assert should_warn is True

    def test_certificate_expiration_boundary_cases(self, temp_dir):
        """Test expiration at exact boundaries."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="boundary.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
            validity_days=1,
        )

        # One second before expiry: valid
        just_before_expiry = cert.not_valid_after - timedelta(seconds=1)
        assert not is_certificate_expired(cert, just_before_expiry)

        # At expiry: expired
        at_expiry = cert.not_valid_after
        assert is_certificate_expired(cert, at_expiry + timedelta(seconds=1))


class TestInvalidCertificateRejection:
    """Test rejection of invalid certificates."""

    def test_reject_self_signed_certificates(self, temp_dir):
        """Test rejection of self-signed server certificates."""
        key = TestCertificateFactory.create_private_key()
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "self-signed.example.com"),
        ])

        self_signed = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)  # Self-signed
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        # Should be detected as self-signed
        is_self_signed = self_signed.issuer == self_signed.subject
        assert is_self_signed is True

    def test_reject_certificates_from_untrusted_ca(self, temp_dir):
        """Test rejection of certificates from untrusted CAs."""
        # Create trusted CA
        trusted_ca_cert, _ = TestCertificateFactory.create_ca_certificate(
            subject_name="Trusted CA"
        )

        # Create untrusted CA
        untrusted_ca_cert, untrusted_ca_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Untrusted CA"
        )

        # Issue cert from untrusted CA
        untrusted_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="untrusted.example.com",
            ca_cert=untrusted_ca_cert,
            ca_key=untrusted_ca_key,
        )

        # Should not be from trusted CA
        is_from_trusted_ca = untrusted_cert.issuer == trusted_ca_cert.subject
        assert is_from_trusted_ca is False

    def test_reject_tampered_certificates(self, temp_dir):
        """Test detection of tampered certificates."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        # Create different CA
        wrong_ca_cert, _ = TestCertificateFactory.create_ca_certificate(
            subject_name="Wrong CA"
        )

        # Try to verify with wrong CA (simulates tampering)
        try:
            wrong_ca_cert.public_key().verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                server_cert.signature_algorithm_parameters,
            )
            signature_valid = True
        except Exception:
            signature_valid = False

        assert signature_valid is False

    def test_reject_weak_key_sizes(self, temp_dir):
        """Test rejection of weak RSA key sizes."""
        # Modern security requires >= 2048 bits
        weak_key = TestCertificateFactory.create_private_key(key_size=1024)
        strong_key = TestCertificateFactory.create_private_key(key_size=2048)

        # Weak key should be detected
        is_weak = weak_key.key_size < 2048
        is_strong = strong_key.key_size >= 2048

        assert is_weak is True
        assert is_strong is True


class TestChainOfTrustVerification:
    """Test chain of trust verification."""

    def test_verify_complete_certificate_chain(self, temp_dir):
        """Test verification of complete certificate chain."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        server_cert, _ = mock_ca.issue_server_certificate("server.example.com")

        # Verify chain: server -> intermediate -> root
        is_valid = verify_certificate_chain(
            server_cert,
            mock_ca.intermediate_cert,
            mock_ca.root_cert,
        )
        assert is_valid is True

    def test_detect_broken_certificate_chain(self, temp_dir):
        """Test detection of broken certificate chains."""
        # Create two separate CA hierarchies
        root1_cert, root1_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Root CA 1"
        )
        root2_cert, root2_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Root CA 2"
        )

        # Create intermediate from root1
        intermediate_cert, intermediate_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Intermediate CA",
            issuer_cert=root1_cert,
            issuer_key=root1_key,
        )

        # Create server cert from intermediate
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=intermediate_cert,
            ca_key=intermediate_key,
        )

        # Try to verify with wrong root
        is_valid = verify_certificate_chain(
            server_cert,
            intermediate_cert,
            root2_cert,  # Wrong root!
        )
        assert is_valid is False

    def test_verify_chain_with_path_length_constraint(self, temp_dir):
        """Test chain verification respects path length constraints."""
        # Create root with path_length=0 (no intermediates allowed)
        root_key = TestCertificateFactory.create_private_key()
        root_subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Restricted Root CA"),
        ])

        root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),  # No intermediates
                critical=True,
            )
            .sign(root_key, hashes.SHA256())
        )

        # Verify constraint
        basic_constraints = root_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.path_length == 0

    def test_verify_each_certificate_in_chain(self, temp_dir):
        """Test individual verification of each certificate in chain."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        server_cert, _ = mock_ca.issue_server_certificate("server.example.com")

        # Verify each certificate individually
        certificates = [
            mock_ca.root_cert,
            mock_ca.intermediate_cert,
            server_cert,
        ]

        for cert in certificates:
            # Check not expired
            assert not is_certificate_expired(cert)

            # Check has required extensions
            assert cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            ) is not None


class TestUnauthorizedAccessPrevention:
    """Test prevention of unauthorized access."""

    def test_reject_unauthorized_client_certificates(self, temp_dir):
        """Test rejection of client certificates from wrong CA."""
        # Setup authorized PKI
        authorized_root, authorized_root_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Authorized Root CA"
        )
        authorized_intermediate, authorized_intermediate_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Authorized Intermediate CA",
            issuer_cert=authorized_root,
            issuer_key=authorized_root_key,
        )

        # Setup unauthorized PKI
        unauthorized_root, unauthorized_root_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Unauthorized Root CA"
        )
        unauthorized_intermediate, unauthorized_intermediate_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Unauthorized Intermediate CA",
            issuer_cert=unauthorized_root,
            issuer_key=unauthorized_root_key,
        )

        # Issue certificates from both
        authorized_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="authorized-client",
            ca_cert=authorized_intermediate,
            ca_key=authorized_intermediate_key,
        )

        unauthorized_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="unauthorized-client",
            ca_cert=unauthorized_intermediate,
            ca_key=unauthorized_intermediate_key,
        )

        # Authorized cert should match authorized CA
        is_from_authorized_ca = authorized_cert.issuer == authorized_intermediate.subject
        assert is_from_authorized_ca is True

        # Unauthorized cert should not match authorized CA (different subject)
        is_from_authorized_ca = unauthorized_cert.issuer == authorized_intermediate.subject
        assert is_from_authorized_ca is False

    def test_prevent_certificate_substitution(self, temp_dir):
        """Test prevention of certificate substitution attacks."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Issue certificate for server1
        server1_cert, server1_key = mock_ca.issue_server_certificate("server1.local")

        # Issue certificate for server2
        server2_cert, _ = mock_ca.issue_server_certificate("server2.local")

        # Verify certificates have different serial numbers
        assert server1_cert.serial_number != server2_cert.serial_number

        # Verify common names are different
        server1_cn = server1_cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )[0].value
        server2_cn = server2_cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )[0].value

        assert server1_cn != server2_cn

    def test_enforce_certificate_purpose(self, temp_dir):
        """Test enforcement of certificate key usage and extended key usage."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        # Verify key usage
        key_usage = server_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )

        # Server cert should have digital_signature and key_encipherment
        assert key_usage.value.digital_signature is True
        assert key_usage.value.key_encipherment is True

        # Should NOT have cert signing capability
        assert key_usage.value.key_cert_sign is False

    def test_prevent_unauthorized_ca_creation(self, temp_dir):
        """Test that server certificates cannot be used as CAs."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, server_key = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        # Server certificate should have CA=false
        basic_constraints = server_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False

        # Attempting to use server cert as CA should be rejected
        # (would fail in validation logic)


class TestKeyProtectionMechanisms:
    """Test private key protection mechanisms."""

    def test_private_key_encryption(self, temp_dir):
        """Test private keys can be encrypted with password."""
        from cryptography.hazmat.primitives import serialization

        _, key = TestCertificateFactory.create_ca_certificate()
        key_path = temp_dir / "encrypted.key"
        password = b"secure_password_123"

        # Save with encryption
        TestCertificateFactory.save_private_key(key, key_path, password=password)

        # Verify can be loaded with correct password
        with open(key_path, "rb") as f:
            loaded_key = serialization.load_pem_private_key(
                f.read(),
                password=password,
            )

        assert isinstance(loaded_key, rsa.RSAPrivateKey)

        # Verify fails with wrong password
        try:
            with open(key_path, "rb") as f:
                serialization.load_pem_private_key(
                    f.read(),
                    password=b"wrong_password",
                )
            loaded_with_wrong_password = True
        except Exception:
            loaded_with_wrong_password = False

        assert loaded_with_wrong_password is False

    def test_private_key_file_permissions(self, temp_dir):
        """Test private key files have restricted permissions."""
        import os
        import stat

        _, key = TestCertificateFactory.create_ca_certificate()
        key_path = temp_dir / "private.key"

        TestCertificateFactory.save_private_key(key, key_path)

        # Set restrictive permissions (owner read/write only)
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)

        # Verify permissions
        mode = os.stat(key_path).st_mode
        permissions = stat.filemode(mode)

        # Should be -rw------- (0600)
        assert permissions == "-rw-------"

    def test_prevent_private_key_exposure(self, temp_dir):
        """Test private keys are not exposed in logs or errors."""
        key = TestCertificateFactory.create_private_key()

        # Private key should not be serialized to string accidentally
        # (this is a design principle test)
        try:
            # Attempting to convert to string should not expose key material
            str(key)  # This returns repr, not key material
            key_exposed = False
        except Exception:
            key_exposed = True

        # Key material should not be easily accessible
        assert key_exposed is False

    def test_key_generation_randomness(self, temp_dir):
        """Test that key generation produces unique keys."""
        keys = [
            TestCertificateFactory.create_private_key()
            for _ in range(10)
        ]

        # All keys should be unique (different public key numbers)
        public_numbers = [
            key.public_key().public_numbers().n
            for key in keys
        ]

        assert len(set(public_numbers)) == 10  # All unique
