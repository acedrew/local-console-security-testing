"""X.509 certificate generation and management utilities."""

from datetime import datetime, timedelta
from typing import Optional, Tuple
from pathlib import Path
import logging

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class X509Utils:
    """Utility class for X.509 certificate operations."""

    @staticmethod
    def generate_private_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
        """
        Generate an RSA private key.

        Args:
            key_size: Size of the RSA key in bits (default: 4096)

        Returns:
            RSA private key object
        """
        logger.info(f"Generating {key_size}-bit RSA private key")
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

    @staticmethod
    def create_root_ca(
        common_name: str,
        organization: str,
        country: str = "US",
        validity_days: int = 3650
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Create a self-signed root CA certificate.

        Args:
            common_name: Common name for the CA
            organization: Organization name
            country: Two-letter country code
            validity_days: Certificate validity period in days

        Returns:
            Tuple of (private_key, certificate)
        """
        logger.info(f"Creating root CA: {common_name}")

        # Generate private key
        private_key = X509Utils.generate_private_key()

        # Create subject and issuer (same for self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
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
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )

        logger.info(f"Root CA created successfully: {common_name}")
        return private_key, cert

    @staticmethod
    def create_intermediate_ca(
        common_name: str,
        organization: str,
        root_private_key: rsa.RSAPrivateKey,
        root_cert: x509.Certificate,
        server_id: str,
        country: str = "US",
        validity_days: int = 365
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Create an intermediate CA certificate signed by root CA.

        Args:
            common_name: Common name for the intermediate CA
            organization: Organization name
            root_private_key: Root CA private key for signing
            root_cert: Root CA certificate
            server_id: Unique identifier for the server
            country: Two-letter country code
            validity_days: Certificate validity period in days

        Returns:
            Tuple of (private_key, certificate)
        """
        logger.info(f"Creating intermediate CA for server: {server_id}")

        # Generate private key
        private_key = X509Utils.generate_private_key()

        # Create subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Server-{server_id}"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(root_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
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
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_private_key.public_key()),
                critical=False,
            )
            .sign(root_private_key, hashes.SHA256(), backend=default_backend())
        )

        logger.info(f"Intermediate CA created for server: {server_id}")
        return private_key, cert

    @staticmethod
    def create_client_certificate(
        common_name: str,
        organization: str,
        ca_private_key: rsa.RSAPrivateKey,
        ca_cert: x509.Certificate,
        validity_hours: int = 1,
        country: str = "US",
        email: Optional[str] = None,
        san_dns_names: Optional[list] = None,
        san_ip_addresses: Optional[list] = None
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Create a client certificate signed by intermediate CA.

        Args:
            common_name: Common name for the client
            organization: Organization name
            ca_private_key: CA private key for signing
            ca_cert: CA certificate
            validity_hours: Certificate validity period in hours
            country: Two-letter country code
            email: Optional email address

        Returns:
            Tuple of (private_key, certificate)
        """
        logger.info(f"Creating client certificate for: {common_name}")

        # Generate private key
        private_key = X509Utils.generate_private_key(key_size=2048)

        # Create subject
        subject_attrs = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]

        if email:
            subject_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

        subject = x509.Name(subject_attrs)

        # Build certificate
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(hours=validity_hours))
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
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
                critical=False,
            )
        )

        # Add Extended Key Usage (SERVER_AUTH if SANs present, otherwise CLIENT_AUTH)
        if san_dns_names or san_ip_addresses:
            # Server certificate
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=True,
            )
        else:
            # Client-only certificate
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )

        # Add Subject Alternative Names if provided
        if san_dns_names or san_ip_addresses:
            san_list = []
            if san_dns_names:
                san_list.extend([x509.DNSName(name) for name in san_dns_names])
            if san_ip_addresses:
                import ipaddress
                san_list.extend([x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ip_addresses])

            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
            logger.info(f"Added SANs: DNS={san_dns_names}, IP={san_ip_addresses}")

        cert = builder.sign(ca_private_key, hashes.SHA256(), backend=default_backend())

        logger.info(f"Client certificate created: {common_name} (valid for {validity_hours} hours)")
        return private_key, cert

    @staticmethod
    def save_private_key(private_key: rsa.RSAPrivateKey, path: Path, password: Optional[bytes] = None):
        """
        Save private key to file.

        Args:
            private_key: RSA private key to save
            path: File path to save to
            password: Optional password for encryption
        """
        logger.info(f"Saving private key to: {path}")

        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pem)
        path.chmod(0o600)  # Restrict permissions

        logger.info(f"Private key saved successfully")

    @staticmethod
    def save_certificate(cert: x509.Certificate, path: Path):
        """
        Save certificate to file.

        Args:
            cert: Certificate to save
            path: File path to save to
        """
        logger.info(f"Saving certificate to: {path}")

        pem = cert.public_bytes(serialization.Encoding.PEM)

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pem)

        logger.info(f"Certificate saved successfully")

    @staticmethod
    def load_private_key(path: Path, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
        """
        Load private key from file.

        Args:
            path: File path to load from
            password: Optional password for decryption

        Returns:
            RSA private key object
        """
        logger.info(f"Loading private key from: {path}")

        pem_data = path.read_bytes()

        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )

        logger.info(f"Private key loaded successfully")
        return private_key

    @staticmethod
    def load_certificate(path: Path) -> x509.Certificate:
        """
        Load certificate from file.

        Args:
            path: File path to load from

        Returns:
            Certificate object
        """
        logger.info(f"Loading certificate from: {path}")

        pem_data = path.read_bytes()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())

        logger.info(f"Certificate loaded successfully")
        return cert
