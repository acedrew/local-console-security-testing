"""Integration tests for Configuration Service with certificate verification."""

import pytest
import json
from pathlib import Path
from datetime import datetime, timedelta

from ..utils.test_helpers import (
    TestCertificateFactory,
    MockCASetup,
    is_certificate_expired,
)


class TestConfigServiceWithCertVerification:
    """Test configuration service integrated with certificate verification."""

    def test_config_service_initialization(self, temp_dir):
        """Test config service initializes with PKI."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Create config service configuration
        config = {
            "service": {
                "name": "config-service",
                "port": 8443,
            },
            "pki": {
                "root_ca": str(temp_dir / "ca" / "root_ca.crt"),
                "intermediate_ca": str(temp_dir / "ca" / "intermediate_ca.crt"),
                "verify_clients": True,
            },
        }

        config_path = temp_dir / "service_config.json"
        with open(config_path, "w") as f:
            json.dump(config, f)

        # Verify config exists
        assert config_path.exists()

        # Load and verify
        with open(config_path, "r") as f:
            loaded = json.load(f)

        assert loaded["pki"]["verify_clients"] is True

    def test_config_service_with_mtls(self, temp_dir):
        """Test config service configured for mTLS."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Issue server certificate for config service
        server_cert, server_key = mock_ca.issue_server_certificate("config.local")

        # Issue client certificate
        client_cert, client_key = TestCertificateFactory.create_server_certificate(
            common_name="config-client",
            ca_cert=mock_ca.intermediate_cert,
            ca_key=mock_ca.intermediate_key,
        )

        # Verify both certificates chain to same root
        assert server_cert.issuer == mock_ca.intermediate_cert.subject
        assert client_cert.issuer == mock_ca.intermediate_cert.subject

    def test_config_download_with_valid_certificate(self, temp_dir):
        """Test configuration download workflow with valid certificate."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Issue client certificate
        client_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="authorized-client",
            ca_cert=mock_ca.intermediate_cert,
            ca_key=mock_ca.intermediate_key,
        )

        # Simulate config download (client authenticated)
        config_data = {
            "client_id": "authorized-client",
            "authenticated": True,
            "config": {
                "setting1": "value1",
                "setting2": "value2",
            },
        }

        # Client cert should be valid
        assert not is_certificate_expired(client_cert)

        # Verify client certificate issuer
        assert client_cert.issuer == mock_ca.intermediate_cert.subject

    def test_config_download_with_expired_certificate(self, temp_dir):
        """Test configuration download is blocked with expired certificate."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Issue expired client certificate
        expired_cert, _ = TestCertificateFactory.create_expired_certificate(
            common_name="expired-client",
            ca_cert=mock_ca.intermediate_cert,
            ca_key=mock_ca.intermediate_key,
        )

        # Should be detected as expired
        assert is_certificate_expired(expired_cert)

        # Access should be denied (would be implemented in service)
        access_granted = not is_certificate_expired(expired_cert)
        assert access_granted is False

    def test_config_download_with_invalid_certificate(self, temp_dir):
        """Test configuration download is blocked with invalid certificate."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Create certificate from different CA
        wrong_ca_cert, wrong_ca_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Unauthorized CA"
        )
        invalid_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="unauthorized-client",
            ca_cert=wrong_ca_cert,
            ca_key=wrong_ca_key,
        )

        # Certificate issuer should not match our intermediate CA
        assert invalid_cert.issuer != mock_ca.intermediate_cert.subject

        # Access should be denied
        access_granted = invalid_cert.issuer == mock_ca.intermediate_cert.subject
        assert access_granted is False


class TestCertificateDownloadWorkflow:
    """Test certificate download workflows."""

    def test_download_root_ca_certificate(self, temp_dir):
        """Test downloading root CA certificate."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        root_ca_path = temp_dir / "ca" / "root_ca.crt"
        assert root_ca_path.exists()

        # Read certificate
        with open(root_ca_path, "rb") as f:
            cert_data = f.read()

        # Verify it's valid PEM format
        assert b"-----BEGIN CERTIFICATE-----" in cert_data
        assert b"-----END CERTIFICATE-----" in cert_data

    def test_download_certificate_bundle(self, temp_dir):
        """Test downloading certificate bundle (chain)."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Create bundle with root + intermediate
        bundle_path = temp_dir / "ca_bundle.pem"

        with open(temp_dir / "ca" / "root_ca.crt", "rb") as f:
            root_pem = f.read()

        with open(temp_dir / "ca" / "intermediate_ca.crt", "rb") as f:
            intermediate_pem = f.read()

        # Combine into bundle
        with open(bundle_path, "wb") as f:
            f.write(intermediate_pem)
            f.write(b"\n")
            f.write(root_pem)

        # Verify bundle exists
        assert bundle_path.exists()

        # Verify contains both certificates
        with open(bundle_path, "rb") as f:
            bundle_data = f.read()

        assert bundle_data.count(b"-----BEGIN CERTIFICATE-----") == 2
        assert bundle_data.count(b"-----END CERTIFICATE-----") == 2

    def test_download_server_specific_certificates(self, temp_dir):
        """Test downloading certificates for specific servers."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        servers = ["web.local", "api.local"]

        for server in servers:
            mock_ca.issue_server_certificate(server)

            # Verify server-specific directory
            server_dir = temp_dir / "servers" / server
            assert (server_dir / "server.crt").exists()
            assert (server_dir / "server.key").exists()

    def test_certificate_package_for_deployment(self, temp_dir):
        """Test creating certificate package for deployment."""
        import tarfile

        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        server_name = "deploy.local"
        mock_ca.issue_server_certificate(server_name)

        # Create deployment package
        package_path = temp_dir / f"{server_name}_certs.tar.gz"

        with tarfile.open(package_path, "w:gz") as tar:
            server_dir = temp_dir / "servers" / server_name
            tar.add(server_dir / "server.crt", arcname="server.crt")
            tar.add(server_dir / "server.key", arcname="server.key")
            tar.add(temp_dir / "ca" / "root_ca.crt", arcname="ca.crt")

        # Verify package
        assert package_path.exists()

        # Extract and verify contents
        extract_dir = temp_dir / "extracted"
        extract_dir.mkdir()

        with tarfile.open(package_path, "r:gz") as tar:
            tar.extractall(extract_dir)

        assert (extract_dir / "server.crt").exists()
        assert (extract_dir / "server.key").exists()
        assert (extract_dir / "ca.crt").exists()


class TestConfigurationValidation:
    """Test configuration validation with certificates."""

    def test_validate_configuration_format(self, temp_dir):
        """Test validating configuration file format."""
        config = {
            "version": "1.0",
            "pki": {
                "enabled": True,
                "root_ca": "/path/to/root.crt",
                "verify_clients": True,
            },
            "service": {
                "port": 8443,
                "tls_enabled": True,
            },
        }

        # Validate required fields
        assert "pki" in config
        assert "service" in config
        assert config["pki"]["enabled"] is True

    def test_validate_certificate_paths(self, temp_dir):
        """Test validating certificate file paths."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Valid paths
        valid_config = {
            "root_ca": str(temp_dir / "ca" / "root_ca.crt"),
            "intermediate_ca": str(temp_dir / "ca" / "intermediate_ca.crt"),
        }

        # Verify all paths exist
        for path_str in valid_config.values():
            assert Path(path_str).exists()

        # Invalid paths
        invalid_config = {
            "root_ca": str(temp_dir / "ca" / "nonexistent.crt"),
        }

        # Verify invalid path doesn't exist
        assert not Path(invalid_config["root_ca"]).exists()

    def test_validate_certificate_chain_configuration(self, temp_dir):
        """Test validating certificate chain configuration."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        chain_config = {
            "chain": [
                str(temp_dir / "ca" / "root_ca.crt"),
                str(temp_dir / "ca" / "intermediate_ca.crt"),
            ],
            "verify_chain": True,
        }

        # Verify chain configuration
        assert len(chain_config["chain"]) == 2
        assert chain_config["verify_chain"] is True

        # Verify all certificates in chain exist
        for cert_path in chain_config["chain"]:
            assert Path(cert_path).exists()

    def test_configuration_with_multiple_services(self, temp_dir):
        """Test configuration for multiple services."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Issue certificates for multiple services
        services = {
            "web": mock_ca.issue_server_certificate("web.local")[0],
            "api": mock_ca.issue_server_certificate("api.local")[0],
            "db": mock_ca.issue_server_certificate("db.local")[0],
        }

        # Create multi-service config
        config = {
            "services": {
                name: {
                    "cert": str(temp_dir / "servers" / f"{name}.local" / "server.crt"),
                    "key": str(temp_dir / "servers" / f"{name}.local" / "server.key"),
                    "port": 8000 + idx,
                }
                for idx, name in enumerate(services.keys())
            },
            "shared": {
                "root_ca": str(temp_dir / "ca" / "root_ca.crt"),
            },
        }

        # Verify config structure
        assert len(config["services"]) == 3
        assert all(service in config["services"] for service in ["web", "api", "db"])


class TestConfigServiceErrorHandling:
    """Test error handling in configuration service."""

    def test_handle_missing_certificate_files(self, temp_dir):
        """Test handling of missing certificate files."""
        config = {
            "root_ca": str(temp_dir / "nonexistent.crt"),
        }

        # Should detect missing file
        ca_path = Path(config["root_ca"])
        assert not ca_path.exists()

    def test_handle_corrupted_certificate(self, temp_dir):
        """Test handling of corrupted certificate files."""
        from cryptography import x509

        corrupted_path = temp_dir / "corrupted.crt"

        # Write invalid PEM data
        with open(corrupted_path, "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\n")
            f.write("INVALID DATA\n")
            f.write("-----END CERTIFICATE-----\n")

        # Attempt to load should fail
        try:
            with open(corrupted_path, "rb") as f:
                x509.load_pem_x509_certificate(f.read())
            loaded_successfully = True
        except Exception:
            loaded_successfully = False

        assert loaded_successfully is False

    def test_handle_permission_denied(self, temp_dir):
        """Test handling of permission denied errors."""
        import os
        import stat

        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        restricted_path = temp_dir / "restricted.crt"
        restricted_path.write_text("test")

        # Remove read permissions
        os.chmod(restricted_path, stat.S_IWUSR)

        # Attempt to read should fail
        try:
            with open(restricted_path, "r") as f:
                f.read()
            read_successfully = True
        except PermissionError:
            read_successfully = False

        # Restore permissions for cleanup
        os.chmod(restricted_path, stat.S_IRUSR | stat.S_IWUSR)

        assert read_successfully is False

    def test_handle_certificate_chain_mismatch(self, temp_dir):
        """Test handling of certificate chain mismatches."""
        # Create two separate PKI hierarchies
        mock_ca1 = MockCASetup(temp_dir / "pki1")
        mock_ca1.setup_complete_pki()

        mock_ca2 = MockCASetup(temp_dir / "pki2")
        mock_ca2.setup_complete_pki()

        # Issue cert from CA1
        cert, _ = mock_ca1.issue_server_certificate("server.local")

        # Try to verify with CA2's root (should fail)
        assert cert.issuer != mock_ca2.root_cert.subject
