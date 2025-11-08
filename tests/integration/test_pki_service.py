"""Integration tests for PKI service end-to-end flows."""

import pytest
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509

from ..utils.test_helpers import (
    TestCertificateFactory,
    MockCASetup,
    verify_certificate_chain,
    is_certificate_expired,
)


class TestEndToEndCertificateIssuance:
    """Test complete certificate issuance workflow."""

    def test_complete_pki_setup_and_issuance(self, temp_dir):
        """Test complete PKI setup and certificate issuance flow."""
        # Step 1: Initialize PKI
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Verify PKI structure
        assert mock_ca.root_cert is not None
        assert mock_ca.intermediate_cert is not None

        # Step 2: Issue server certificate
        server_cert, server_key = mock_ca.issue_server_certificate("app.example.com")

        # Step 3: Verify complete chain
        is_valid = verify_certificate_chain(
            server_cert,
            mock_ca.intermediate_cert,
            mock_ca.root_cert,
        )
        assert is_valid is True

        # Step 4: Verify certificates are saved
        assert (temp_dir / "ca" / "root_ca.crt").exists()
        assert (temp_dir / "ca" / "intermediate_ca.crt").exists()
        assert (temp_dir / "servers" / "app.example.com" / "server.crt").exists()
        assert (temp_dir / "servers" / "app.example.com" / "server.key").exists()

    def test_issue_multiple_server_certificates(self, temp_dir):
        """Test issuing multiple server certificates from same PKI."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        servers = ["web.example.com", "api.example.com", "db.example.com"]
        certificates = []

        for server in servers:
            cert, _ = mock_ca.issue_server_certificate(server)
            certificates.append(cert)

            # Verify each certificate
            is_valid = verify_certificate_chain(
                cert,
                mock_ca.intermediate_cert,
                mock_ca.root_cert,
            )
            assert is_valid is True

        # Verify all certificates exist
        for server in servers:
            server_dir = temp_dir / "servers" / server
            assert (server_dir / "server.crt").exists()
            assert (server_dir / "server.key").exists()

    def test_certificate_renewal_flow(self, temp_dir):
        """Test certificate renewal process."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        server_name = "renew.example.com"

        # Issue initial certificate
        cert1, _ = mock_ca.issue_server_certificate(server_name)
        serial1 = cert1.serial_number

        # Issue renewed certificate (same server, new cert)
        cert2, _ = mock_ca.issue_server_certificate(server_name)
        serial2 = cert2.serial_number

        # Certificates should have different serial numbers
        assert serial1 != serial2

        # Both should be valid
        assert not is_certificate_expired(cert1)
        assert not is_certificate_expired(cert2)

    def test_intermediary_ca_per_server_isolation(self, temp_dir):
        """Test creating separate intermediate CAs per server for isolation."""
        root_cert, root_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Root CA"
        )

        servers = ["server1", "server2", "server3"]
        server_certs = {}

        for server in servers:
            # Create unique intermediate CA per server
            intermediate_cert, intermediate_key = TestCertificateFactory.create_ca_certificate(
                subject_name=f"Intermediate CA - {server}",
                issuer_cert=root_cert,
                issuer_key=root_key,
            )

            # Issue server certificate
            server_cert, _ = TestCertificateFactory.create_server_certificate(
                common_name=f"{server}.example.com",
                ca_cert=intermediate_cert,
                ca_key=intermediate_key,
            )

            server_certs[server] = {
                "intermediate": intermediate_cert,
                "server": server_cert,
            }

        # Verify each server has unique intermediate CA
        intermediate_subjects = [
            data["intermediate"].subject
            for data in server_certs.values()
        ]
        assert len(set(intermediate_subjects)) == len(servers)

        # Verify all intermediates chain to same root
        for data in server_certs.values():
            assert data["intermediate"].issuer == root_cert.subject


class TestClientAuthentication:
    """Test client authentication with mTLS."""

    def test_client_certificate_generation(self, temp_dir):
        """Test generating client certificates for mTLS."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Issue client certificate
        client_cert, client_key = TestCertificateFactory.create_server_certificate(
            common_name="client-device-001",
            ca_cert=mock_ca.intermediate_cert,
            ca_key=mock_ca.intermediate_key,
        )

        # Verify client cert
        assert client_cert is not None
        assert client_cert.issuer == mock_ca.intermediate_cert.subject

    def test_multiple_client_certificates(self, temp_dir):
        """Test issuing multiple client certificates."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        clients = ["device-001", "device-002", "device-003"]
        client_certs = []

        for client_id in clients:
            cert, _ = TestCertificateFactory.create_server_certificate(
                common_name=client_id,
                ca_cert=mock_ca.intermediate_cert,
                ca_key=mock_ca.intermediate_key,
            )
            client_certs.append(cert)

        # All should have unique serial numbers
        serial_numbers = [cert.serial_number for cert in client_certs]
        assert len(set(serial_numbers)) == len(clients)

    def test_client_certificate_validation(self, temp_dir):
        """Test validating client certificates during mTLS."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Issue valid client certificate
        valid_client_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="valid-client",
            ca_cert=mock_ca.intermediate_cert,
            ca_key=mock_ca.intermediate_key,
        )

        # Create invalid client certificate (from different CA)
        wrong_ca_cert, wrong_ca_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Wrong CA"
        )
        invalid_client_cert, _ = TestCertificateFactory.create_server_certificate(
            common_name="invalid-client",
            ca_cert=wrong_ca_cert,
            ca_key=wrong_ca_key,
        )

        # Valid client should pass verification
        assert valid_client_cert.issuer == mock_ca.intermediate_cert.subject

        # Invalid client should fail verification
        assert invalid_client_cert.issuer != mock_ca.intermediate_cert.subject

    def test_expired_client_certificate_rejection(self, temp_dir):
        """Test rejection of expired client certificates."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Create expired client certificate
        expired_cert, _ = TestCertificateFactory.create_expired_certificate(
            common_name="expired-client",
            ca_cert=mock_ca.intermediate_cert,
            ca_key=mock_ca.intermediate_key,
        )

        # Should be detected as expired
        assert is_certificate_expired(expired_cert)


class TestMultiContainerCommunication:
    """Test certificate usage in multi-container environments."""

    def test_server_to_server_mtls(self, temp_dir):
        """Test mTLS between multiple servers."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Create certificates for multiple services
        services = ["api", "database", "cache"]
        service_certs = {}

        for service in services:
            cert, key = mock_ca.issue_server_certificate(f"{service}.internal")
            service_certs[service] = {"cert": cert, "key": key}

        # Verify all services can be authenticated
        for service, data in service_certs.items():
            is_valid = verify_certificate_chain(
                data["cert"],
                mock_ca.intermediate_cert,
                mock_ca.root_cert,
            )
            assert is_valid is True

    def test_shared_root_ca_across_containers(self, temp_dir):
        """Test sharing root CA across multiple containers."""
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Root CA should be shareable
        root_ca_path = temp_dir / "ca" / "root_ca.crt"
        assert root_ca_path.exists()

        # Multiple services can use same root for verification
        services = ["service1", "service2", "service3"]
        for service in services:
            cert, _ = mock_ca.issue_server_certificate(f"{service}.local")

            # All should chain to same root
            is_valid = verify_certificate_chain(
                cert,
                mock_ca.intermediate_cert,
                mock_ca.root_cert,
            )
            assert is_valid is True

    def test_container_specific_intermediate_cas(self, temp_dir):
        """Test using container-specific intermediate CAs."""
        root_cert, root_key = TestCertificateFactory.create_ca_certificate(
            subject_name="Shared Root CA"
        )

        containers = ["web-container", "api-container", "db-container"]
        container_intermediates = {}

        for container in containers:
            # Each container gets its own intermediate CA
            intermediate_cert, intermediate_key = TestCertificateFactory.create_ca_certificate(
                subject_name=f"CA for {container}",
                issuer_cert=root_cert,
                issuer_key=root_key,
            )
            container_intermediates[container] = {
                "cert": intermediate_cert,
                "key": intermediate_key,
            }

        # Verify isolation: each container has unique intermediate
        intermediate_cns = [
            data["cert"].subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0].value
            for data in container_intermediates.values()
        ]
        assert len(set(intermediate_cns)) == len(containers)


class TestConfigurationPersistence:
    """Test configuration persistence and recovery."""

    def test_save_and_load_pki_state(self, temp_dir):
        """Test saving and loading complete PKI state."""
        import json

        # Setup PKI
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Save configuration
        config = {
            "root_ca": {
                "cert_path": str(temp_dir / "ca" / "root_ca.crt"),
                "key_path": str(temp_dir / "ca" / "root_ca.key"),
            },
            "intermediate_ca": {
                "cert_path": str(temp_dir / "ca" / "intermediate_ca.crt"),
                "key_path": str(temp_dir / "ca" / "intermediate_ca.key"),
            },
            "created_at": datetime.utcnow().isoformat(),
        }

        config_path = temp_dir / "pki_config.json"
        with open(config_path, "w") as f:
            json.dump(config, f)

        # Verify config can be loaded
        with open(config_path, "r") as f:
            loaded_config = json.load(f)

        assert loaded_config["root_ca"]["cert_path"] == config["root_ca"]["cert_path"]
        assert Path(loaded_config["root_ca"]["cert_path"]).exists()

    def test_recover_from_saved_state(self, temp_dir):
        """Test recovering PKI from saved state."""
        from cryptography.hazmat.primitives import serialization

        # Create and save PKI
        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        root_ca_path = temp_dir / "ca" / "root_ca.crt"
        intermediate_ca_path = temp_dir / "ca" / "intermediate_ca.crt"

        # Load certificates from disk
        with open(root_ca_path, "rb") as f:
            from cryptography import x509
            loaded_root = x509.load_pem_x509_certificate(f.read())

        with open(intermediate_ca_path, "rb") as f:
            loaded_intermediate = x509.load_pem_x509_certificate(f.read())

        # Verify loaded certificates match originals
        assert loaded_root.serial_number == mock_ca.root_cert.serial_number
        assert loaded_intermediate.serial_number == mock_ca.intermediate_cert.serial_number

    def test_certificate_inventory_tracking(self, temp_dir):
        """Test tracking issued certificates."""
        import json

        mock_ca = MockCASetup(temp_dir)
        mock_ca.setup_complete_pki()

        # Issue multiple certificates
        servers = ["web.local", "api.local", "db.local"]
        inventory = []

        for server in servers:
            cert, _ = mock_ca.issue_server_certificate(server)
            inventory.append({
                "common_name": server,
                "serial_number": cert.serial_number,
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat(),
                "issued_at": datetime.utcnow().isoformat(),
            })

        # Save inventory
        inventory_path = temp_dir / "certificate_inventory.json"
        with open(inventory_path, "w") as f:
            json.dump(inventory, f, indent=2)

        # Verify inventory
        with open(inventory_path, "r") as f:
            loaded_inventory = json.load(f)

        assert len(loaded_inventory) == len(servers)
        assert all("serial_number" in item for item in loaded_inventory)
