"""Unit tests for CA Manager component."""

import pytest
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from ..utils.test_helpers import (
    TestCertificateFactory,
    MockCASetup,
    is_certificate_expired,
)


class TestCAInitialization:
    """Test CA initialization and key generation."""

    def test_generate_root_ca_key(self, temp_dir):
        """Test root CA key generation."""
        key = TestCertificateFactory.create_private_key(key_size=4096)
        assert key is not None
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_generate_root_ca_certificate(self, temp_dir, ca_config):
        """Test root CA certificate generation."""
        cert, key = TestCertificateFactory.create_ca_certificate(
            subject_name=ca_config["root_ca"]["common_name"],
            validity_days=ca_config["root_ca"]["validity_days"],
        )

        assert cert is not None
        assert isinstance(cert, x509.Certificate)

        # Verify certificate properties
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "Test Root CA"

        # Verify it's self-signed
        assert cert.issuer == cert.subject

        # Verify validity period
        validity_duration = cert.not_valid_after - cert.not_valid_before
        assert validity_duration.days >= 3649  # ~10 years

    def test_root_ca_basic_constraints(self, temp_dir):
        """Test root CA has correct basic constraints."""
        cert, _ = TestCertificateFactory.create_ca_certificate()

        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.critical is True

    def test_root_ca_key_usage(self, temp_dir):
        """Test root CA has correct key usage."""
        cert, _ = TestCertificateFactory.create_ca_certificate()

        key_usage = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.KEY_USAGE
        )
        assert key_usage.value.key_cert_sign is True
        assert key_usage.value.crl_sign is True
        assert key_usage.value.digital_signature is True

    def test_ca_persistence(self, temp_dir):
        """Test CA certificate and key can be saved and loaded."""
        cert, key = TestCertificateFactory.create_ca_certificate()

        cert_path = temp_dir / "test_ca.crt"
        key_path = temp_dir / "test_ca.key"

        TestCertificateFactory.save_certificate(cert, cert_path)
        TestCertificateFactory.save_private_key(key, key_path)

        assert cert_path.exists()
        assert key_path.exists()

        # Verify file is not empty
        assert cert_path.stat().st_size > 0
        assert key_path.stat().st_size > 0

    def test_generate_intermediate_ca(self, temp_dir):
        """Test intermediate CA generation."""
        # Create root CA
        root_cert, root_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Test Root CA"
        )

        # Create intermediate CA
        intermediate_cert, intermediate_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Test Intermediate CA",
            validity_days=1825,
            issuer_cert=root_cert,
            issuer_key=root_key,
        )

        assert intermediate_cert is not None
        assert intermediate_cert.issuer == root_cert.subject
        assert intermediate_cert.subject != root_cert.subject

    def test_intermediate_ca_per_server(self, temp_dir):
        """Test generating unique intermediate CA for each server."""
        root_cert, root_key = TestCertificateFactory.create_ca_certificate()

        servers = ["server1", "server2", "server3"]
        intermediate_cas = {}

        for server in servers:
            cert, key = TestCertificateFactory.create_ca_certificate(
                subject_name=f"Intermediate CA for {server}",
                issuer_cert=root_cert,
                issuer_key=root_key,
            )
            intermediate_cas[server] = (cert, key)

        # Verify each server has unique intermediate CA
        assert len(intermediate_cas) == 3

        # Verify all are different
        subjects = [cert.subject for cert, _ in intermediate_cas.values()]
        assert len(set(subjects)) == 3


class TestCertificateIssuance:
    """Test certificate issuance with correct TTL."""

    def test_issue_server_certificate_with_default_ttl(self, temp_dir, cert_config):
        """Test server certificate issued with default TTL."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        server_cert, server_key = TestCertificateFactory.create_server_certificate(
            common_name="test.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
            validity_days=cert_config["ttl"],
        )

        validity_duration = server_cert.not_valid_after - server_cert.not_valid_before
        assert validity_duration.days >= 364  # ~1 year (365 days)
        assert validity_duration.days <= 366

    def test_issue_server_certificate_with_custom_ttl(self, temp_dir):
        """Test server certificate issued with custom TTL."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        custom_ttl = 90  # 90 days
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="short-lived.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
            validity_days=custom_ttl,
        )

        validity_duration = server_cert.not_valid_after - server_cert.not_valid_before
        assert validity_duration.days >= custom_ttl - 1
        assert validity_duration.days <= custom_ttl + 1

    def test_certificate_not_valid_before_is_current(self, temp_dir):
        """Test certificate not_valid_before is set to current time."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        before_creation = datetime.utcnow()
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="test.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
        )
        after_creation = datetime.utcnow()

        assert server_cert.not_valid_before >= before_creation - timedelta(seconds=1)
        assert server_cert.not_valid_before <= after_creation + timedelta(seconds=1)

    def test_certificate_serial_number_uniqueness(self, temp_dir):
        """Test each certificate has unique serial number."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        serial_numbers = set()
        for i in range(10):
            cert, _ = TestCertificateFactory.create_server_certificate(
                common_name=f"server{i}.example.com",
                ca_cert=ca_cert,
                ca_key=ca_key,
            )
            serial_numbers.add(cert.serial_number)

        # All serial numbers should be unique
        assert len(serial_numbers) == 10

    def test_certificate_with_subject_alternative_names(self, temp_dir):
        """Test certificate with multiple SANs."""
        ca_cert, ca_key = TestCertificateFactory.create_ca_certificate()

        san_list = ["test.example.com", "www.test.example.com", "api.test.example.com"]
        server_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="test.example.com",
            ca_cert=ca_cert,
            ca_key=ca_key,
            san_dns=san_list,
        )

        san_ext = server_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        dns_names = [name.value for name in san_ext.value]

        for expected_name in san_list:
            assert expected_name in dns_names


class TestConfigurationPersistence:
    """Test configuration persistence."""

    def test_save_ca_configuration(self, temp_dir, ca_config):
        """Test CA configuration can be saved."""
        import json

        # Convert Path objects to strings for JSON serialization
        serializable_config = {
            "ca_dir": str(ca_config["ca_dir"]),
            "root_ca": ca_config["root_ca"],
            "intermediate_ca": ca_config["intermediate_ca"],
            "server_cert": ca_config["server_cert"],
        }

        config_path = temp_dir / "ca_config.json"
        with open(config_path, "w") as f:
            json.dump(serializable_config, f)

        assert config_path.exists()

        # Verify can be loaded back
        with open(config_path, "r") as f:
            loaded_config = json.load(f)

        assert loaded_config["root_ca"] == serializable_config["root_ca"]
        assert loaded_config["intermediate_ca"] == serializable_config["intermediate_ca"]

    def test_load_ca_from_disk(self, temp_dir):
        """Test CA can be loaded from disk after save."""
        from cryptography.hazmat.primitives import serialization

        # Create and save CA
        cert, key = TestCertificateFactory.create_ca_certificate()
        cert_path = temp_dir / "ca.crt"
        key_path = temp_dir / "ca.key"

        TestCertificateFactory.save_certificate(cert, cert_path)
        TestCertificateFactory.save_private_key(key, key_path)

        # Load back
        with open(cert_path, "rb") as f:
            loaded_cert = x509.load_pem_x509_certificate(f.read())

        with open(key_path, "rb") as f:
            loaded_key = serialization.load_pem_private_key(f.read(), password=None)

        assert loaded_cert.serial_number == cert.serial_number
        assert isinstance(loaded_key, rsa.RSAPrivateKey)

    def test_encrypted_key_persistence(self, temp_dir):
        """Test private key can be saved with password encryption."""
        from cryptography.hazmat.primitives import serialization

        _, key = TestCertificateFactory.create_ca_certificate()
        key_path = temp_dir / "encrypted_ca.key"
        password = b"test_password_123"

        TestCertificateFactory.save_private_key(key, key_path, password=password)

        # Verify can be loaded with password
        with open(key_path, "rb") as f:
            loaded_key = serialization.load_pem_private_key(
                f.read(), password=password
            )

        assert isinstance(loaded_key, rsa.RSAPrivateKey)

    def test_directory_structure_creation(self, temp_dir):
        """Test proper directory structure is created."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Verify directory structure
        assert (temp_dir / "ca").exists()
        assert (temp_dir / "ca" / "root_ca.crt").exists()
        assert (temp_dir / "ca" / "root_ca.key").exists()
        assert (temp_dir / "ca" / "intermediate_ca.crt").exists()
        assert (temp_dir / "ca" / "intermediate_ca.key").exists()
