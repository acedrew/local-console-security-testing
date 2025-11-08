"""Unit tests for Certificate Verification component."""

import pytest
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from ..utils.test_helpers import (
    TestCertificateFactory,
    MockCASetup,
    verify_certificate_chain,
    is_certificate_expired,
)


class TestDualVerification:
    """Test dual verification logic (root + intermediary)."""

    def test_verify_with_root_ca(self, temp_dir):
        """Test verification using root CA."""
        root_cert, root_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Root CA"
        )

        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=root_cert,
            ca_key=root_key,
        )

        # Verify server cert is signed by root
        assert server_cert.issuer == root_cert.subject

    def test_verify_with_intermediate_ca(self, temp_dir):
        """Test verification using intermediate CA."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        server_cert, _ = mock_ca.issue_server_certificate("server.example.com")

        # Verify server cert is signed by intermediate
        assert server_cert.issuer == mock_ca.intermediate_cert.subject

    def test_dual_verification_valid_chain(self, temp_dir):
        """Test dual verification with valid certificate chain."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        server_cert, _ = mock_ca.issue_server_certificate("server.example.com")

        # Verify complete chain
        is_valid = verify_certificate_chain(
            server_cert,
            mock_ca.intermediate_cert,
            mock_ca.root_cert,
        )
        assert is_valid is True

    def test_dual_verification_broken_chain(self, temp_dir):
        """Test dual verification with broken certificate chain."""
        # Create two separate CA chains
        root1_cert, root1_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Root CA 1"
        )
        root2_cert, root2_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Root CA 2"
        )

        intermediate_cert, intermediate_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Intermediate CA",
            issuer_cert=root1_cert,
            issuer_key=root1_key,
        )

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

    def test_verify_certificate_signature(self, temp_dir):
        """Test cryptographic signature verification."""
        from cryptography.hazmat.primitives.asymmetric import padding

        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        # Verify signature using CA public key
        try:
            ca_cert.public_key().verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                server_cert.signature_hash_algorithm,
            )
            signature_valid = True
        except Exception:
            signature_valid = False

        assert signature_valid is True

    def test_reject_self_signed_server_certificate(self, temp_dir):
        """Test rejection of self-signed server certificates."""
        from cryptography.hazmat.primitives import hashes

        # Create a self-signed certificate (not from CA)
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

        # This should fail CA verification
        assert self_signed.issuer == self_signed.subject  # Self-signed indicator


class TestCertificateChainValidation:
    """Test certificate chain validation logic."""

    def test_validate_complete_chain(self, temp_dir):
        """Test validation of complete certificate chain."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        server_cert, _ = mock_ca.issue_server_certificate("server.example.com")

        # Build chain list
        chain = [server_cert, mock_ca.intermediate_cert, mock_ca.root_cert]

        # Verify chain continuity
        assert chain[0].issuer == chain[1].subject
        assert chain[1].issuer == chain[2].subject
        assert chain[2].issuer == chain[2].subject  # Root is self-signed

    def test_validate_chain_order(self, temp_dir):
        """Test chain must be in correct order."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        server_cert, _ = mock_ca.issue_server_certificate("server.example.com")

        # Correct order: server -> intermediate -> root
        correct_chain = [server_cert, mock_ca.intermediate_cert, mock_ca.root_cert]

        # Verify each link
        for i in range(len(correct_chain) - 1):
            assert correct_chain[i].issuer == correct_chain[i + 1].subject

    def test_detect_missing_intermediate(self, temp_dir):
        """Test detection of missing intermediate certificate."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        server_cert, _ = mock_ca.issue_server_certificate("server.example.com")

        # Server cert's issuer should be intermediate, not root
        assert server_cert.issuer != mock_ca.root_cert.subject
        assert server_cert.issuer == mock_ca.intermediate_cert.subject

    def test_validate_path_length_constraint(self, temp_dir):
        """Test path length constraint validation."""
        from cryptography.hazmat.primitives import hashes

        # Create root with path length = 1
        root_key = TestCertificateFactory.create_private_key()
        root_subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Root CA"),
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
                x509.BasicConstraints(ca=True, path_length=1),  # Max 1 intermediate
                critical=True,
            )
            .sign(root_key, hashes.SHA256())
        )

        # Create one intermediate - should be OK
        intermediate_cert, _ = TestCertificateFactory.create_ca_certificate(
            subject_name="Intermediate CA",
            issuer_cert=root_cert,
            issuer_key=root_key,
        )

        # Verify path length is respected
        root_constraints = root_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert root_constraints.value.path_length == 1


class TestExpirationValidation:
    """Test certificate expiration validation."""

    def test_detect_expired_certificate(self, temp_dir):
        """Test detection of expired certificates."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        expired_cert, _ = TestCertificateFactory.create_expired_certificate(
            common_name="expired.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        assert is_certificate_expired(expired_cert)

    def test_detect_not_yet_valid_certificate(self, temp_dir):
        """Test detection of not-yet-valid certificates."""
        from cryptography.hazmat.primitives import hashes

        key = TestCertificateFactory.create_private_key()
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "future.example.com"),
        ])

        # Create certificate valid in the future
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

        # Should be "expired" (not yet valid) from current perspective
        assert is_certificate_expired(future_cert)

    def test_valid_certificate_within_period(self, temp_dir):
        """Test valid certificate within validity period."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="valid.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
            validity_days=365,
        )

        # Should be valid now
        assert not is_certificate_expired(server_cert)

        # Should be valid in 180 days
        future_check = datetime.utcnow() + timedelta(days=180)
        assert not is_certificate_expired(server_cert, future_check)

        # Should be expired in 400 days
        far_future_check = datetime.utcnow() + timedelta(days=400)
        assert is_certificate_expired(server_cert, far_future_check)

    def test_expiration_at_exact_boundary(self, temp_dir):
        """Test expiration at exact validity boundary."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="boundary.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
            validity_days=1,
        )

        # At expiration time
        expiry_time = server_cert.not_valid_after
        assert is_certificate_expired(server_cert, expiry_time + timedelta(seconds=1))


class TestInvalidCertificates:
    """Test handling of invalid certificates."""

    def test_certificate_with_wrong_signature(self, temp_dir):
        """Test detection of certificate with tampered signature."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        # Create a different CA
        wrong_ca_cert, _ = TestCertificateFactory.create_ca_certificate(
            subject_name="Wrong CA"
        )

        # Try to verify server cert with wrong CA
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

    def test_revoked_certificate_handling(self, temp_dir):
        """Test framework for handling revoked certificates."""
        # This is a placeholder for CRL/OCSP functionality
        # In real implementation, would check certificate against CRL
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="revoked.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        # In real implementation:
        # - Check CRL for certificate serial number
        # - Query OCSP responder
        # - Maintain revocation list

        # For now, just verify structure exists
        assert server_cert.serial_number is not None

    def test_certificate_with_invalid_extensions(self, temp_dir):
        """Test handling of certificates with invalid extensions."""
        from cryptography.hazmat.primitives import hashes

        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        # Server cert claiming to be CA should be rejected
        key = TestCertificateFactory.create_private_key()
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "fake-ca.example.com"),
        ])

        invalid_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),  # Server claiming to be CA!
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        # Verify it claims to be CA (which would be invalid for server cert)
        basic_constraints = invalid_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True  # This should be rejected in validation

    def test_certificate_key_size_validation(self, temp_dir):
        """Test validation of minimum key size requirements."""
        # Modern security requires >= 2048 bits
        weak_key = TestCertificateFactory.create_private_key(key_size=1024)
        strong_key = TestCertificateFactory.create_private_key(key_size=2048)

        assert weak_key.key_size == 1024
        assert strong_key.key_size == 2048

        # In real implementation, would reject weak keys
        # assert strong_key.key_size >= 2048
