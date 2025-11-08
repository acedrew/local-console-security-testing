"""Certificate Authority management module."""

from pathlib import Path
from typing import Optional, Dict
import logging
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from ..crypto_utils import X509Utils, CertificateVerifier

logger = logging.getLogger(__name__)


class CAManager:
    """Manages Certificate Authority operations and storage."""

    def __init__(self, storage_path: Path):
        """
        Initialize CA Manager.

        Args:
            storage_path: Base path for certificate storage
        """
        self.storage_path = Path(storage_path)
        self.root_ca_path = self.storage_path / "root_ca"
        self.intermediate_ca_path = self.storage_path / "intermediate_cas"

        # Create directories
        self.root_ca_path.mkdir(parents=True, exist_ok=True)
        self.intermediate_ca_path.mkdir(parents=True, exist_ok=True)

        # CA cache
        self._root_private_key: Optional[rsa.RSAPrivateKey] = None
        self._root_cert: Optional[x509.Certificate] = None
        self._intermediate_cas: Dict[str, tuple] = {}

        logger.info(f"CA Manager initialized with storage path: {storage_path}")

    def initialize_root_ca(
        self,
        organization: str = "AceIoT",
        common_name: str = "AceIoT Root CA",
        country: str = "US",
        force: bool = False
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Initialize or load root CA.

        Args:
            organization: Organization name
            common_name: Common name for root CA
            country: Two-letter country code
            force: Force recreation of root CA

        Returns:
            Tuple of (private_key, certificate)
        """
        root_key_path = self.root_ca_path / "root_ca.key"
        root_cert_path = self.root_ca_path / "root_ca.crt"

        # Check if root CA already exists
        if not force and root_key_path.exists() and root_cert_path.exists():
            logger.info("Loading existing root CA")
            self._root_private_key = X509Utils.load_private_key(root_key_path)
            self._root_cert = X509Utils.load_certificate(root_cert_path)
            return self._root_private_key, self._root_cert

        # Create new root CA
        logger.info("Creating new root CA")
        private_key, cert = X509Utils.create_root_ca(
            common_name=common_name,
            organization=organization,
            country=country,
            validity_days=3650  # 10 years
        )

        # Save to disk
        X509Utils.save_private_key(private_key, root_key_path)
        X509Utils.save_certificate(cert, root_cert_path)

        # Cache
        self._root_private_key = private_key
        self._root_cert = cert

        logger.info(f"Root CA initialized: {common_name}")
        return private_key, cert

    def get_root_ca(self) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Get root CA (load from cache or disk).

        Returns:
            Tuple of (private_key, certificate)

        Raises:
            FileNotFoundError: If root CA not initialized
        """
        if self._root_private_key and self._root_cert:
            return self._root_private_key, self._root_cert

        root_key_path = self.root_ca_path / "root_ca.key"
        root_cert_path = self.root_ca_path / "root_ca.crt"

        if not root_key_path.exists() or not root_cert_path.exists():
            raise FileNotFoundError("Root CA not initialized. Call initialize_root_ca() first.")

        self._root_private_key = X509Utils.load_private_key(root_key_path)
        self._root_cert = X509Utils.load_certificate(root_cert_path)

        return self._root_private_key, self._root_cert

    def create_intermediate_ca(
        self,
        server_id: str,
        organization: str = "AceIoT",
        common_name: Optional[str] = None,
        country: str = "US",
        validity_days: int = 365
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Create an intermediate CA for a specific server.

        Args:
            server_id: Unique server identifier
            organization: Organization name
            common_name: Custom common name (defaults to server_id)
            country: Two-letter country code
            validity_days: Certificate validity in days

        Returns:
            Tuple of (private_key, certificate)
        """
        logger.info(f"Creating intermediate CA for server: {server_id}")

        # Get root CA
        root_private_key, root_cert = self.get_root_ca()

        # Generate common name if not provided
        if not common_name:
            common_name = f"{organization} Intermediate CA - {server_id}"

        # Create intermediate CA
        private_key, cert = X509Utils.create_intermediate_ca(
            common_name=common_name,
            organization=organization,
            root_private_key=root_private_key,
            root_cert=root_cert,
            server_id=server_id,
            country=country,
            validity_days=validity_days
        )

        # Save to disk
        server_path = self.intermediate_ca_path / server_id
        server_path.mkdir(parents=True, exist_ok=True)

        key_path = server_path / "intermediate_ca.key"
        cert_path = server_path / "intermediate_ca.crt"

        X509Utils.save_private_key(private_key, key_path)
        X509Utils.save_certificate(cert, cert_path)

        # Cache
        self._intermediate_cas[server_id] = (private_key, cert)

        logger.info(f"Intermediate CA created for server: {server_id}")
        return private_key, cert

    def get_intermediate_ca(self, server_id: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Get intermediate CA for a server.

        Args:
            server_id: Server identifier

        Returns:
            Tuple of (private_key, certificate)

        Raises:
            FileNotFoundError: If intermediate CA not found
        """
        # Check cache
        if server_id in self._intermediate_cas:
            return self._intermediate_cas[server_id]

        # Load from disk
        server_path = self.intermediate_ca_path / server_id
        key_path = server_path / "intermediate_ca.key"
        cert_path = server_path / "intermediate_ca.crt"

        if not key_path.exists() or not cert_path.exists():
            raise FileNotFoundError(f"Intermediate CA not found for server: {server_id}")

        private_key = X509Utils.load_private_key(key_path)
        cert = X509Utils.load_certificate(cert_path)

        # Cache
        self._intermediate_cas[server_id] = (private_key, cert)

        return private_key, cert

    def list_intermediate_cas(self) -> list[str]:
        """
        List all intermediate CA server IDs.

        Returns:
            List of server IDs
        """
        if not self.intermediate_ca_path.exists():
            return []

        return [
            p.name for p in self.intermediate_ca_path.iterdir()
            if p.is_dir() and (p / "intermediate_ca.crt").exists()
        ]

    def get_ca_chain(self, server_id: str) -> str:
        """
        Get complete CA chain in PEM format.

        Args:
            server_id: Server identifier

        Returns:
            PEM-encoded certificate chain (intermediate + root)
        """
        _, intermediate_cert = self.get_intermediate_ca(server_id)
        _, root_cert = self.get_root_ca()

        intermediate_pem = intermediate_cert.public_bytes(serialization.Encoding.PEM).decode()
        root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()

        return intermediate_pem + root_pem

    def verify_ca_chain(self, server_id: str) -> bool:
        """
        Verify intermediate CA chain.

        Args:
            server_id: Server identifier

        Returns:
            True if chain is valid

        Raises:
            Exception: If verification fails
        """
        _, intermediate_cert = self.get_intermediate_ca(server_id)
        _, root_cert = self.get_root_ca()

        # Verify intermediate is signed by root
        CertificateVerifier.verify_certificate_chain(
            intermediate_cert,
            root_cert,
            root_cert
        )

        return True

    def get_root_ca_info(self) -> dict:
        """
        Get root CA information.

        Returns:
            Dictionary with root CA details
        """
        _, root_cert = self.get_root_ca()

        return {
            "subject": root_cert.subject.rfc4514_string(),
            "serial_number": root_cert.serial_number,
            "not_valid_before": root_cert.not_valid_before.isoformat(),
            "not_valid_after": root_cert.not_valid_after.isoformat(),
            "fingerprint_sha256": CertificateVerifier.get_certificate_fingerprint(root_cert),
        }

    def get_intermediate_ca_info(self, server_id: str) -> dict:
        """
        Get intermediate CA information.

        Args:
            server_id: Server identifier

        Returns:
            Dictionary with intermediate CA details
        """
        _, cert = self.get_intermediate_ca(server_id)

        return {
            "server_id": server_id,
            "subject": cert.subject.rfc4514_string(),
            "serial_number": cert.serial_number,
            "not_valid_before": cert.not_valid_before.isoformat(),
            "not_valid_after": cert.not_valid_after.isoformat(),
            "fingerprint_sha256": CertificateVerifier.get_certificate_fingerprint(cert),
        }
