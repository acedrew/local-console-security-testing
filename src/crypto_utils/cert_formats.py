"""Certificate format conversion utilities."""

import logging
from pathlib import Path
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class CertificateFormatConverter:
    """Convert certificates between different formats."""

    @staticmethod
    def pem_to_der(pem_data: bytes) -> bytes:
        """
        Convert PEM certificate to DER format.

        Args:
            pem_data: PEM-encoded certificate bytes

        Returns:
            DER-encoded certificate bytes
        """
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        return cert.public_bytes(serialization.Encoding.DER)

    @staticmethod
    def pem_to_pkcs12(
        cert_pem: bytes,
        key_pem: bytes,
        ca_chain_pem: Optional[bytes] = None,
        password: Optional[bytes] = None,
        friendly_name: Optional[bytes] = None
    ) -> bytes:
        """
        Convert PEM certificate and key to PKCS12 format (.p12/.pfx).

        Args:
            cert_pem: PEM-encoded certificate
            key_pem: PEM-encoded private key
            ca_chain_pem: Optional PEM-encoded CA certificate chain
            password: Optional password to encrypt the PKCS12 file
            friendly_name: Optional friendly name for the certificate

        Returns:
            PKCS12-encoded data bytes
        """
        # Load certificate
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

        # Load private key
        key = serialization.load_pem_private_key(
            key_pem,
            password=None,
            backend=default_backend()
        )

        # Load CA chain if provided
        ca_certs = []
        if ca_chain_pem:
            # Split PEM chain into individual certificates
            pem_str = ca_chain_pem.decode('utf-8')
            cert_blocks = []
            current_block = []

            for line in pem_str.split('\n'):
                if '-----BEGIN CERTIFICATE-----' in line:
                    current_block = [line]
                elif '-----END CERTIFICATE-----' in line:
                    current_block.append(line)
                    cert_blocks.append('\n'.join(current_block))
                    current_block = []
                elif current_block:
                    current_block.append(line)

            # Load each certificate in the chain
            for cert_block in cert_blocks:
                ca_cert = x509.load_pem_x509_certificate(
                    cert_block.encode('utf-8'),
                    default_backend()
                )
                ca_certs.append(ca_cert)

        # Create PKCS12
        pkcs12_data = pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=key,
            cert=cert,
            cas=ca_certs if ca_certs else None,
            encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        )

        return pkcs12_data

    @staticmethod
    def create_bundle(
        cert_pem: bytes,
        key_pem: bytes,
        ca_chain_pem: Optional[bytes] = None
    ) -> bytes:
        """
        Create a bundle file with certificate, key, and CA chain.

        Args:
            cert_pem: PEM-encoded certificate
            key_pem: PEM-encoded private key
            ca_chain_pem: Optional PEM-encoded CA certificate chain

        Returns:
            Combined PEM bundle
        """
        bundle = b""

        # Add certificate
        bundle += b"# Client Certificate\n"
        bundle += cert_pem
        bundle += b"\n"

        # Add private key
        bundle += b"# Private Key\n"
        bundle += key_pem
        bundle += b"\n"

        # Add CA chain
        if ca_chain_pem:
            bundle += b"# CA Certificate Chain\n"
            bundle += ca_chain_pem
            bundle += b"\n"

        return bundle

    @staticmethod
    def create_curl_bundle(
        cert_pem: bytes,
        key_pem: bytes,
        ca_chain_pem: Optional[bytes] = None
    ) -> dict:
        """
        Create files suitable for curl usage.

        Returns:
            Dict with 'cert', 'key', 'cacert', and 'bundle' keys
        """
        return {
            'cert': cert_pem,  # --cert
            'key': key_pem,     # --key
            'cacert': ca_chain_pem if ca_chain_pem else b"",  # --cacert
            'bundle': CertificateFormatConverter.create_bundle(
                cert_pem, key_pem, ca_chain_pem
            )  # Combined bundle
        }

    @staticmethod
    def create_nginx_bundle(
        cert_pem: bytes,
        ca_chain_pem: Optional[bytes] = None
    ) -> bytes:
        """
        Create certificate bundle for nginx (cert + chain).

        Args:
            cert_pem: PEM-encoded certificate
            ca_chain_pem: Optional PEM-encoded CA certificate chain

        Returns:
            Combined certificate and chain
        """
        bundle = cert_pem
        if ca_chain_pem:
            bundle += b"\n" + ca_chain_pem
        return bundle

    @staticmethod
    def get_format_extension(format_type: str) -> str:
        """
        Get file extension for a given format type.

        Args:
            format_type: Format type (pem, der, p12, pfx, bundle, etc.)

        Returns:
            File extension including the dot
        """
        extensions = {
            'pem': '.pem',
            'crt': '.crt',
            'cer': '.cer',
            'der': '.der',
            'p12': '.p12',
            'pfx': '.pfx',
            'bundle': '.bundle.pem',
            'curl': '.curl.pem',
            'nginx': '.nginx.pem',
            'key': '.key'
        }
        return extensions.get(format_type.lower(), '.bin')

    @staticmethod
    def get_content_type(format_type: str) -> str:
        """
        Get HTTP content type for a given format.

        Args:
            format_type: Format type

        Returns:
            MIME content type
        """
        content_types = {
            'pem': 'application/x-pem-file',
            'crt': 'application/x-x509-ca-cert',
            'der': 'application/x-x509-ca-cert',
            'p12': 'application/x-pkcs12',
            'pfx': 'application/x-pkcs12',
            'bundle': 'application/x-pem-file',
            'key': 'application/x-pem-file'
        }
        return content_types.get(format_type.lower(), 'application/octet-stream')
