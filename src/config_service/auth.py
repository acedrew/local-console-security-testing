"""mTLS authentication for Streamlit config interface."""

import ssl
import logging
from pathlib import Path
from typing import Optional
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from crypto_utils.verification import CertificateVerifier, CertificateVerificationError

logger = logging.getLogger(__name__)


class MTLSAuthenticator:
    """Handles mTLS client certificate authentication."""

    def __init__(self, root_ca_path: Path, intermediate_ca_path: Path):
        """
        Initialize mTLS authenticator.

        Args:
            root_ca_path: Path to root CA certificate
            intermediate_ca_path: Path to intermediate CA certificate
        """
        self.root_ca_path = Path(root_ca_path)
        self.intermediate_ca_path = Path(intermediate_ca_path)

        # Load CA certificates
        self.root_cert = self._load_certificate(root_ca_path)
        self.intermediate_cert = self._load_certificate(intermediate_ca_path)

        logger.info("mTLS Authenticator initialized")

    def _load_certificate(self, path: Path) -> x509.Certificate:
        """Load certificate from file."""
        pem_data = path.read_bytes()
        return x509.load_pem_x509_certificate(pem_data, default_backend())

    def create_ssl_context(
        self,
        certfile: Path,
        keyfile: Path,
        require_client_cert: bool = True
    ) -> ssl.SSLContext:
        """
        Create SSL context for mTLS.

        Args:
            certfile: Path to server certificate
            keyfile: Path to server private key
            require_client_cert: Whether to require client certificates

        Returns:
            Configured SSL context
        """
        logger.info("Creating SSL context for mTLS")

        # Create SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        # Load server certificate and key
        context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))

        if require_client_cert:
            # Require client certificates
            context.verify_mode = ssl.CERT_REQUIRED

            # Load CA chain for client verification
            # Create temporary combined CA file
            ca_chain_path = certfile.parent / "ca_chain.pem"
            ca_chain = self.root_cert.public_bytes(ssl.Encoding.PEM).decode()
            ca_chain += self.intermediate_cert.public_bytes(ssl.Encoding.PEM).decode()
            ca_chain_path.write_text(ca_chain)

            context.load_verify_locations(cafile=str(ca_chain_path))
        else:
            context.verify_mode = ssl.CERT_NONE

        # Set TLS version and ciphers
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4')

        logger.info("SSL context created successfully")
        return context

    def verify_client_certificate(self, cert_pem: str) -> dict:
        """
        Verify client certificate against CA chain.

        Args:
            cert_pem: PEM-encoded client certificate

        Returns:
            Dictionary with client information

        Raises:
            CertificateVerificationError: If verification fails
        """
        logger.info("Verifying client certificate")

        # Load client certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # Verify chain
        info = CertificateVerifier.verify_client_certificate(
            cert,
            self.intermediate_cert,
            self.root_cert
        )

        logger.info(f"Client certificate verified: {info['subject']['common_name']}")
        return info

    def extract_client_info_from_request(self, request) -> Optional[dict]:
        """
        Extract and verify client certificate from HTTP request.

        Args:
            request: HTTP request object

        Returns:
            Client information dictionary or None
        """
        # This would extract the client certificate from the SSL connection
        # Implementation depends on the web framework being used
        # For Streamlit, this might need to be handled differently

        # Example for standard WSGI:
        # cert_pem = request.environ.get('SSL_CLIENT_CERT')

        # For now, return None - would be implemented based on deployment
        logger.warning("Client certificate extraction not implemented for this framework")
        return None

    def require_authentication(self, func):
        """
        Decorator to require mTLS authentication.

        Args:
            func: Function to decorate

        Returns:
            Decorated function
        """
        def wrapper(*args, **kwargs):
            # This would check for valid client certificate
            # Implementation depends on the web framework
            logger.info("Authentication check (placeholder)")
            return func(*args, **kwargs)

        return wrapper
