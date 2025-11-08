"""Certificate issuance and management module."""

from pathlib import Path
from typing import Optional
import logging
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..crypto_utils import X509Utils, CertificateVerifier
from .ca_manager import CAManager

logger = logging.getLogger(__name__)


class CertificateIssuer:
    """Handles client certificate issuance and management."""

    def __init__(self, ca_manager: CAManager, cert_storage_path: Path):
        """
        Initialize Certificate Issuer.

        Args:
            ca_manager: CA Manager instance
            cert_storage_path: Path for storing issued certificates
        """
        self.ca_manager = ca_manager
        self.cert_storage_path = Path(cert_storage_path)
        self.cert_storage_path.mkdir(parents=True, exist_ok=True)

        logger.info(f"Certificate Issuer initialized with storage: {cert_storage_path}")

    def issue_client_certificate(
        self,
        common_name: str,
        organization: str,
        server_id: str,
        email: Optional[str] = None,
        validity_hours: int = 1,
        country: str = "US",
        san_dns_names: Optional[list] = None,
        san_ip_addresses: Optional[list] = None
    ) -> dict:
        """
        Issue a client certificate.

        Args:
            common_name: Common name for the certificate
            organization: Organization name
            server_id: Server ID for intermediate CA
            email: Optional email address
            validity_hours: Certificate validity in hours
            country: Two-letter country code

        Returns:
            Dictionary containing certificate details
        """
        logger.info(f"Issuing client certificate for: {common_name} (server: {server_id})")

        # Get intermediate CA for this server
        ca_private_key, ca_cert = self.ca_manager.get_intermediate_ca(server_id)

        # Create client certificate
        private_key, cert = X509Utils.create_client_certificate(
            common_name=common_name,
            organization=organization,
            ca_private_key=ca_private_key,
            ca_cert=ca_cert,
            validity_hours=validity_hours,
            country=country,
            email=email,
            san_dns_names=san_dns_names,
            san_ip_addresses=san_ip_addresses
        )

        # Get full CA chain
        ca_chain = self.ca_manager.get_ca_chain(server_id)

        # Convert to PEM format
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        # Calculate fingerprint
        fingerprint = CertificateVerifier.get_certificate_fingerprint(cert)

        # Store certificate (optional, for audit trail)
        self._store_certificate(cert, server_id)

        logger.info(f"Client certificate issued: {common_name} (serial: {cert.serial_number})")

        return {
            "certificate": cert_pem,
            "private_key": key_pem,
            "ca_chain": ca_chain,
            "serial_number": str(cert.serial_number),  # Convert to string for JavaScript compatibility
            "not_valid_before": cert.not_valid_before,
            "not_valid_after": cert.not_valid_after,
            "fingerprint_sha256": fingerprint,
        }

    def verify_client_certificate(
        self,
        cert_pem: str,
        server_id: str
    ) -> dict:
        """
        Verify a client certificate against CA chain.

        Args:
            cert_pem: PEM-encoded certificate
            server_id: Server ID for intermediate CA

        Returns:
            Dictionary containing verification results

        Raises:
            Exception: If verification fails
        """
        logger.info(f"Verifying client certificate for server: {server_id}")

        # Load certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode())

        # Get CA chain
        _, intermediate_cert = self.ca_manager.get_intermediate_ca(server_id)
        _, root_cert = self.ca_manager.get_root_ca()

        # Verify chain
        info = CertificateVerifier.verify_client_certificate(
            cert,
            intermediate_cert,
            root_cert
        )

        # Add fingerprint
        info["fingerprint_sha256"] = CertificateVerifier.get_certificate_fingerprint(cert)

        logger.info(f"Client certificate verified: {info['subject']['common_name']}")
        return info

    def _store_certificate(self, cert: x509.Certificate, server_id: str):
        """
        Store issued certificate for audit trail.

        Args:
            cert: Certificate to store
            server_id: Server ID
        """
        server_path = self.cert_storage_path / server_id
        server_path.mkdir(parents=True, exist_ok=True)

        # Use serial number as filename
        cert_file = server_path / f"{cert.serial_number}.crt"

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_file.write_bytes(cert_pem)

        logger.debug(f"Certificate stored: {cert_file}")

    def list_issued_certificates(self, server_id: str) -> list[dict]:
        """
        List all certificates issued for a server.

        Args:
            server_id: Server ID

        Returns:
            List of certificate information dictionaries
        """
        server_path = self.cert_storage_path / server_id

        if not server_path.exists():
            return []

        certs = []
        for cert_file in server_path.glob("*.crt"):
            try:
                cert = X509Utils.load_certificate(cert_file)

                # Check if still valid
                now = datetime.utcnow()
                is_valid = cert.not_valid_before <= now <= cert.not_valid_after

                subject = cert.subject
                common_name = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value \
                    if subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME) else "Unknown"

                certs.append({
                    "serial_number": str(cert.serial_number),  # Convert to string for JavaScript compatibility
                    "common_name": common_name,
                    "not_valid_before": cert.not_valid_before.isoformat(),
                    "not_valid_after": cert.not_valid_after.isoformat(),
                    "is_valid": is_valid,
                    "fingerprint_sha256": CertificateVerifier.get_certificate_fingerprint(cert),
                })
            except Exception as e:
                logger.error(f"Error loading certificate {cert_file}: {e}")
                continue

        return sorted(certs, key=lambda x: x["not_valid_before"], reverse=True)

    def get_certificate_info(self, serial_number: int, server_id: str) -> Optional[dict]:
        """
        Get information about a specific certificate.

        Args:
            serial_number: Certificate serial number
            server_id: Server ID

        Returns:
            Certificate information or None if not found
        """
        cert_file = self.cert_storage_path / server_id / f"{serial_number}.crt"

        if not cert_file.exists():
            return None

        try:
            cert = X509Utils.load_certificate(cert_file)

            # Verify the certificate
            info = self.verify_client_certificate(
                cert.public_bytes(serialization.Encoding.PEM).decode(),
                server_id
            )

            return info
        except Exception as e:
            logger.error(f"Error loading certificate {cert_file}: {e}")
            return None
