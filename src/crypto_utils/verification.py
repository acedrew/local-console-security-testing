"""Certificate chain verification utilities."""

from typing import List, Optional
from datetime import datetime
import logging

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)


class CertificateVerificationError(Exception):
    """Exception raised when certificate verification fails."""
    pass


class CertificateVerifier:
    """Utility class for certificate chain verification."""

    @staticmethod
    def verify_certificate_chain(
        cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate
    ) -> bool:
        """
        Verify a complete certificate chain (client -> intermediate -> root).

        Args:
            cert: Client certificate to verify
            intermediate_cert: Intermediate CA certificate
            root_cert: Root CA certificate

        Returns:
            True if verification succeeds

        Raises:
            CertificateVerificationError: If verification fails
        """
        logger.info("Verifying certificate chain")

        try:
            # Verify client cert against intermediate CA
            CertificateVerifier._verify_signature(cert, intermediate_cert)
            logger.info("Client certificate signature verified against intermediate CA")

            # Verify intermediate cert against root CA
            CertificateVerifier._verify_signature(intermediate_cert, root_cert)
            logger.info("Intermediate CA signature verified against root CA")

            # Verify root cert is self-signed
            CertificateVerifier._verify_signature(root_cert, root_cert)
            logger.info("Root CA self-signature verified")

            # Verify validity periods
            CertificateVerifier._verify_validity(cert)
            CertificateVerifier._verify_validity(intermediate_cert)
            CertificateVerifier._verify_validity(root_cert)
            logger.info("All certificates are within validity period")

            # Verify certificate purposes
            CertificateVerifier._verify_ca_constraints(intermediate_cert, is_root=False)
            CertificateVerifier._verify_ca_constraints(root_cert, is_root=True)
            logger.info("CA constraints verified")

            logger.info("Certificate chain verification successful")
            return True

        except Exception as e:
            logger.error(f"Certificate chain verification failed: {str(e)}")
            raise CertificateVerificationError(f"Chain verification failed: {str(e)}")

    @staticmethod
    def _verify_signature(cert: x509.Certificate, issuer_cert: x509.Certificate):
        """
        Verify that cert is signed by issuer_cert.

        Args:
            cert: Certificate to verify
            issuer_cert: Issuing certificate

        Raises:
            CertificateVerificationError: If signature verification fails
        """
        try:
            issuer_public_key = issuer_cert.public_key()

            # Verify the signature
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_parameters
            )
        except InvalidSignature:
            raise CertificateVerificationError(
                f"Invalid signature: {cert.subject.rfc4514_string()} not signed by {issuer_cert.subject.rfc4514_string()}"
            )
        except Exception as e:
            raise CertificateVerificationError(f"Signature verification error: {str(e)}")

    @staticmethod
    def _verify_validity(cert: x509.Certificate):
        """
        Verify certificate is within its validity period.

        Args:
            cert: Certificate to verify

        Raises:
            CertificateVerificationError: If certificate is expired or not yet valid
        """
        now = datetime.utcnow()

        if now < cert.not_valid_before:
            raise CertificateVerificationError(
                f"Certificate not yet valid: {cert.subject.rfc4514_string()} "
                f"(valid from {cert.not_valid_before})"
            )

        if now > cert.not_valid_after:
            raise CertificateVerificationError(
                f"Certificate expired: {cert.subject.rfc4514_string()} "
                f"(expired on {cert.not_valid_after})"
            )

    @staticmethod
    def _verify_ca_constraints(cert: x509.Certificate, is_root: bool = False):
        """
        Verify CA basic constraints.

        Args:
            cert: Certificate to verify
            is_root: Whether this is a root CA

        Raises:
            CertificateVerificationError: If CA constraints are invalid
        """
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            ).value

            if not basic_constraints.ca:
                raise CertificateVerificationError(
                    f"Certificate is not a CA: {cert.subject.rfc4514_string()}"
                )

            if is_root:
                # Root CA should have path_length >= 1 or None
                if basic_constraints.path_length is not None and basic_constraints.path_length < 1:
                    raise CertificateVerificationError(
                        f"Invalid path length for root CA: {basic_constraints.path_length}"
                    )
            else:
                # Intermediate CA should have path_length = 0
                if basic_constraints.path_length != 0:
                    logger.warning(
                        f"Intermediate CA path length is {basic_constraints.path_length}, expected 0"
                    )

        except x509.ExtensionNotFound:
            raise CertificateVerificationError(
                f"Basic constraints extension not found in CA certificate"
            )

    @staticmethod
    def verify_client_certificate(
        cert: x509.Certificate,
        intermediate_cert: x509.Certificate,
        root_cert: x509.Certificate
    ) -> dict:
        """
        Verify a client certificate and extract information.

        Args:
            cert: Client certificate to verify
            intermediate_cert: Intermediate CA certificate
            root_cert: Root CA certificate

        Returns:
            Dictionary containing certificate information

        Raises:
            CertificateVerificationError: If verification fails
        """
        logger.info(f"Verifying client certificate: {cert.subject.rfc4514_string()}")

        # Verify the chain
        CertificateVerifier.verify_certificate_chain(cert, intermediate_cert, root_cert)

        # Extract certificate information
        subject = cert.subject

        info = {
            "valid": True,
            "subject": {
                "common_name": subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
                if subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME) else None,
                "organization": subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
                if subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME) else None,
                "country": subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value
                if subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME) else None,
            },
            "issuer": {
                "common_name": cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
                if cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME) else None,
            },
            "serial_number": cert.serial_number,
            "not_valid_before": cert.not_valid_before.isoformat(),
            "not_valid_after": cert.not_valid_after.isoformat(),
        }

        # Check for email in subject
        email_attrs = subject.get_attributes_for_oid(x509.oid.NameOID.EMAIL_ADDRESS)
        if email_attrs:
            info["subject"]["email"] = email_attrs[0].value

        logger.info(f"Client certificate verified successfully: {info['subject']['common_name']}")
        return info

    @staticmethod
    def get_certificate_fingerprint(cert: x509.Certificate, algorithm: str = "sha256") -> str:
        """
        Get certificate fingerprint.

        Args:
            cert: Certificate
            algorithm: Hash algorithm (sha256, sha1, etc.)

        Returns:
            Hex-encoded fingerprint
        """
        if algorithm == "sha256":
            digest = cert.fingerprint(hashes.SHA256())
        elif algorithm == "sha1":
            digest = cert.fingerprint(hashes.SHA1())
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        return digest.hex()
