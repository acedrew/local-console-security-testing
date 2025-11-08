"""Unit tests for Certificate Issuer component."""

import pytest
from datetime import datetime, timedelta
from cryptography import x509

from ..utils.test_helpers import (
    TestCertificateFactory,
    MockCASetup,
    is_certificate_expired,
)


class TestCertificateGeneration:
    """Test certificate generation functionality."""

    def test_generate_server_certificate(self, temp_dir):
        """Test basic server certificate generation."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        server_cert, server_key = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        assert server_cert is not None
        assert server_key is not None
        assert server_cert.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )[0].value == "server.example.com"

    def test_certificate_signed_by_ca(self, temp_dir):
        """Test certificate is properly signed by CA."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="test.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        # Verify issuer matches CA subject
        assert server_cert.issuer == ca_cert.subject

    def test_certificate_public_key_matches_private_key(self, temp_dir):
        """Test certificate public key matches generated private key."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, server_key = TestCertificateFactory.create_server_certificate(
            common_name="test.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        # Public key from cert should match private key
        cert_public_key = server_cert.public_key()
        private_public_key = server_key.public_key()

        # Compare public key numbers
        assert (
            cert_public_key.public_numbers().n ==
            private_public_key.public_numbers().n
        )

    def test_multiple_certificates_from_same_ca(self, temp_dir):
        """Test issuing multiple certificates from same CA."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        servers = ["web.example.com", "api.example.com", "db.example.com"]
        certificates = []

        for server in servers:
            cert, key = TestCertificateFactory.create_server_certificate(
                common_name=server,
                ca_cert=ca_cert,
                ca_key=ca_key,
            )
            certificates.append(cert)

        # All certificates should have same issuer
        for cert in certificates:
            assert cert.issuer == ca_cert.subject

        # All certificates should have unique serial numbers
        serial_numbers = [cert.serial_number for cert in certificates]
        assert len(set(serial_numbers)) == len(servers)


class TestCertificateAttributes:
    """Test certificate attributes and extensions."""

    def test_server_certificate_is_not_ca(self, temp_dir):
        """Test server certificate has CA=false."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        basic_constraints = server_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False

    def test_server_certificate_key_usage(self, temp_dir):
        """Test server certificate has correct key usage."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        key_usage = server_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )
        assert key_usage.value.digital_signature is True
        assert key_usage.value.key_encipherment is True
        assert key_usage.value.key_cert_sign is False

    def test_certificate_subject_fields(self, temp_dir):
        """Test certificate contains correct subject fields."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="test.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        subject = server_cert.subject
        cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        assert len(cn) == 1
        assert cn[0].value == "test.example.com"

    def test_certificate_with_wildcard_cn(self, temp_dir):
        """Test certificate with wildcard common name."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="*.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        cn = server_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        assert cn == "*.example.com"


class TestCertificateValidity:
    """Test certificate validity periods."""

    def test_certificate_validity_period(self, temp_dir):
        """Test certificate has correct validity period."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        validity_days = 180
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="test.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
            validity_days=validity_days,
        )

        duration = server_cert.not_valid_after - server_cert.not_valid_before
        assert abs(duration.days - validity_days) <= 1

    def test_certificate_not_expired_immediately(self, temp_dir):
        """Test newly created certificate is not expired."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="test.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        assert not is_certificate_expired(server_cert)

    def test_certificate_expires_in_future(self, temp_dir):
        """Test certificate expiration is in the future."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="test.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
            validity_days=365,
        )

        now = datetime.utcnow()
        future = now + timedelta(days=400)

        assert not is_certificate_expired(server_cert, now)
        assert is_certificate_expired(server_cert, future)

    def test_short_lived_certificate(self, temp_dir):
        """Test creating short-lived certificates."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        # 1 day certificate
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="short-lived.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
            validity_days=1,
        )

        duration = server_cert.not_valid_after - server_cert.not_valid_before
        assert duration.days <= 1

    def test_expired_certificate_detection(self, temp_dir):
        """Test detection of expired certificates."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()
        expired_cert, _ = TestCertificateFactory.create_expired_certificate(
            common_name="expired.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )

        assert is_certificate_expired(expired_cert)


class TestCertificateChain:
    """Test certificate chain functionality."""

    def test_two_level_chain(self, temp_dir):
        """Test certificate chain with root and server cert."""
        root_cert, root_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Root CA"
        )

        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=root_cert,
            ca_key=root_key,
        )

        # Server cert should be signed by root
        assert server_cert.issuer == root_cert.subject

    def test_three_level_chain(self, temp_dir):
        """Test certificate chain with root, intermediate, and server cert."""
        # Create root CA
        root_cert, root_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Root CA"
        )

        # Create intermediate CA
        intermediate_cert, intermediate_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Intermediate CA",
            issuer_cert=root_cert,
            issuer_key=root_key,
        )

        # Create server cert
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=intermediate_cert,
            ca_key=intermediate_key,
        )

        # Verify chain
        assert server_cert.issuer == intermediate_cert.subject
        assert intermediate_cert.issuer == root_cert.subject
        assert root_cert.issuer == root_cert.subject  # Self-signed

    def test_chain_with_different_ttls(self, temp_dir):
        """Test certificate chain with different TTLs."""
        # Root: 10 years
        root_cert, root_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Root CA",
            validity_days=3650,
        )

        # Intermediate: 5 years
        intermediate_cert, intermediate_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Intermediate CA",
            validity_days=1825,
            issuer_cert=root_cert,
            issuer_key=root_key,
        )

        # Server: 1 year
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="server.example.com",
            ca_cert=intermediate_cert,
            ca_key=intermediate_key,
            validity_days=365,
        )

        # Verify TTLs
        root_duration = root_cert.not_valid_after - root_cert.not_valid_before
        intermediate_duration = intermediate_cert.not_valid_after - intermediate_cert.not_valid_before
        server_duration = server_cert.not_valid_after - server_cert.not_valid_before

        assert root_duration.days >= 3649
        assert intermediate_duration.days >= 1824
        assert server_duration.days >= 364
