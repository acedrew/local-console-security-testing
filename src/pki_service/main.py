"""FastAPI PKI Service - Main application."""

from pathlib import Path
from datetime import datetime
from typing import Optional
import logging

from fastapi import FastAPI, HTTPException, status, Depends, Header, Form
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request

from .models import (
    CertificateRequest,
    IntermediateCARequest,
    CertificateResponse,
    IntermediateCAResponse,
    CertificateInfo,
    HealthResponse,
    ErrorResponse,
)
from .ca_manager import CAManager
from .cert_issuer import CertificateIssuer
from ..crypto_utils.cert_formats import CertificateFormatConverter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AceIoT PKI Service",
    description="Public Key Infrastructure service for certificate management",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Storage paths
STORAGE_BASE = Path.home() / ".aceiot" / "pki"
CA_STORAGE = STORAGE_BASE / "ca"
CERT_STORAGE = STORAGE_BASE / "certificates"
TEMP_CERT_STORAGE = STORAGE_BASE / "temp_downloads"

# Create temp storage directory
TEMP_CERT_STORAGE.mkdir(parents=True, exist_ok=True)

# Initialize managers
ca_manager = CAManager(CA_STORAGE)
cert_issuer = CertificateIssuer(ca_manager, CERT_STORAGE)
format_converter = CertificateFormatConverter()

# Initialize templates
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


# Dependency for API key authentication (simple example)
def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    """
    Verify API key from header.

    In production, implement proper authentication.
    """
    # For now, just check if key is provided
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )
    return x_api_key


@app.on_event("startup")
async def startup_event():
    """Initialize root CA on startup."""
    try:
        logger.info("Initializing PKI service...")
        ca_manager.initialize_root_ca()
        logger.info("PKI service initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize PKI service: {e}")
        raise


@app.get("/", response_model=dict)
async def root():
    """Root endpoint."""
    return {
        "service": "AceIoT PKI Service",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    try:
        # Check if root CA is initialized
        root_ca_initialized = False
        try:
            ca_manager.get_root_ca()
            root_ca_initialized = True
        except FileNotFoundError:
            pass

        # Count intermediate CAs
        intermediate_cas = len(ca_manager.list_intermediate_cas())

        return HealthResponse(
            status="healthy",
            root_ca_initialized=root_ca_initialized,
            intermediate_cas=intermediate_cas,
            timestamp=datetime.utcnow()
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unhealthy"
        )


@app.post("/ca/intermediate", response_model=IntermediateCAResponse)
async def create_intermediate_ca(
    request: IntermediateCARequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Create a new intermediate CA for a server.

    Requires API key authentication.
    """
    try:
        logger.info(f"Creating intermediate CA for server: {request.server_id}")

        # Create intermediate CA
        _, cert = ca_manager.create_intermediate_ca(
            server_id=request.server_id,
            organization=request.organization,
            common_name=request.common_name,
            validity_days=request.validity_days
        )

        # Get CA chain
        ca_chain = ca_manager.get_ca_chain(request.server_id)

        # Get certificate PEM
        from cryptography.hazmat.primitives import serialization
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        # Get fingerprint
        from ..crypto_utils import CertificateVerifier
        fingerprint = CertificateVerifier.get_certificate_fingerprint(cert)

        return IntermediateCAResponse(
            server_id=request.server_id,
            certificate=cert_pem,
            ca_chain=ca_chain,
            serial_number=cert.serial_number,
            not_valid_before=cert.not_valid_before,
            not_valid_after=cert.not_valid_after,
            fingerprint_sha256=fingerprint
        )

    except Exception as e:
        logger.error(f"Failed to create intermediate CA: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create intermediate CA: {str(e)}"
        )


@app.get("/ca/intermediate", response_model=list[dict])
async def list_intermediate_cas():
    """List all intermediate CAs."""
    try:
        server_ids = ca_manager.list_intermediate_cas()

        cas = []
        for server_id in server_ids:
            info = ca_manager.get_intermediate_ca_info(server_id)
            cas.append(info)

        return cas

    except Exception as e:
        logger.error(f"Failed to list intermediate CAs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list intermediate CAs: {str(e)}"
        )


@app.get("/ca/intermediate/{server_id}", response_model=dict)
async def get_intermediate_ca(server_id: str):
    """Get intermediate CA information."""
    try:
        info = ca_manager.get_intermediate_ca_info(server_id)
        return info

    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Intermediate CA not found for server: {server_id}"
        )
    except Exception as e:
        logger.error(f"Failed to get intermediate CA info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get intermediate CA info: {str(e)}"
        )


@app.get("/ca/root", response_model=dict)
async def get_root_ca():
    """Get root CA information."""
    try:
        info = ca_manager.get_root_ca_info()
        return info

    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Root CA not initialized"
        )
    except Exception as e:
        logger.error(f"Failed to get root CA info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get root CA info: {str(e)}"
        )


@app.get("/ca/root/certificate", response_class=JSONResponse)
async def download_root_ca():
    """Download root CA certificate in PEM format."""
    try:
        from cryptography.hazmat.primitives import serialization
        _, root_cert = ca_manager.get_root_ca()

        cert_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()

        return JSONResponse(
            content={"certificate": cert_pem},
            headers={"Content-Type": "application/json"}
        )

    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Root CA not initialized"
        )
    except Exception as e:
        logger.error(f"Failed to download root CA: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download root CA: {str(e)}"
        )


@app.post("/certificates/issue", response_model=CertificateResponse)
async def issue_certificate(
    request: CertificateRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Issue a new client certificate.

    Requires API key authentication.
    """
    try:
        logger.info(f"Issuing certificate for: {request.common_name}")

        # Issue certificate
        cert_data = cert_issuer.issue_client_certificate(
            common_name=request.common_name,
            organization=request.organization,
            server_id=request.server_id,
            email=request.email,
            validity_hours=request.validity_hours,
            san_dns_names=request.san_dns_names,
            san_ip_addresses=request.san_ip_addresses
        )

        return CertificateResponse(**cert_data)

    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Intermediate CA not found for server: {request.server_id}"
        )
    except Exception as e:
        logger.error(f"Failed to issue certificate: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to issue certificate: {str(e)}"
        )


@app.post("/certificates/verify", response_model=CertificateInfo)
async def verify_certificate(
    certificate: str,
    server_id: str
):
    """
    Verify a client certificate.

    Args:
        certificate: PEM-encoded certificate
        server_id: Server ID for intermediate CA
    """
    try:
        logger.info(f"Verifying certificate for server: {server_id}")

        # Verify certificate
        info = cert_issuer.verify_client_certificate(certificate, server_id)

        return CertificateInfo(**info)

    except Exception as e:
        logger.error(f"Certificate verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Certificate verification failed: {str(e)}"
        )


@app.get("/certificates/{server_id}", response_model=list[dict])
async def list_certificates(server_id: str):
    """List all certificates issued for a server."""
    try:
        certs = cert_issuer.list_issued_certificates(server_id)
        return certs

    except Exception as e:
        logger.error(f"Failed to list certificates: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list certificates: {str(e)}"
        )


@app.get("/certificates/{server_id}/{serial_number}", response_model=CertificateInfo)
async def get_certificate_info(server_id: str, serial_number: int):
    """Get information about a specific certificate."""
    try:
        info = cert_issuer.get_certificate_info(serial_number, server_id)

        if not info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Certificate not found: {serial_number}"
            )

        return CertificateInfo(**info)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get certificate info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get certificate info: {str(e)}"
        )


# ============================================================================
# UI Routes for Certificate Download
# ============================================================================

@app.get("/ui/download", response_class=HTMLResponse)
async def download_ui(request: Request):
    """Render certificate download page."""
    return templates.TemplateResponse("download.html", {"request": request})


@app.post("/ui/download/issue", response_class=HTMLResponse)
async def issue_certificate_ui(
    request: Request,
    common_name: str = Form(...),
    server_id: str = Form(...),
    email: Optional[str] = Form(None),
    validity_hours: int = Form(1)
):
    """Issue certificate from UI form and show download page."""
    try:
        # Ensure intermediate CA exists
        intermediate_cas = ca_manager.list_intermediate_cas()
        if server_id not in intermediate_cas:
            # Auto-create intermediate CA
            logger.info(f"Auto-creating intermediate CA for server: {server_id}")
            ca_manager.create_intermediate_ca(
                server_id=server_id,
                organization="AceIoT",
                common_name=f"Intermediate CA - {server_id}",
                validity_days=365
            )

        # Issue certificate
        cert_data = cert_issuer.issue_client_certificate(
            common_name=common_name,
            organization="AceIoT",
            server_id=server_id,
            email=email,
            validity_hours=validity_hours
        )

        # Save certificate data to temp storage for downloads
        cert_id = str(cert_data['serial_number'])
        temp_dir = TEMP_CERT_STORAGE / cert_id
        temp_dir.mkdir(parents=True, exist_ok=True)

        # Generate a random password for P12 files (macOS security requires it)
        import secrets
        import string
        p12_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))

        # Save files
        (temp_dir / "cert.pem").write_text(cert_data['certificate'])
        (temp_dir / "key.pem").write_text(cert_data['private_key'])
        (temp_dir / "ca-chain.pem").write_text(cert_data['ca_chain'])
        (temp_dir / "p12_password.txt").write_text(p12_password)  # Save password for download endpoint

        # Calculate time remaining
        from datetime import datetime
        expiry = cert_data['not_valid_after']
        now = datetime.utcnow()
        time_delta = expiry - now
        hours = int(time_delta.total_seconds() // 3600)
        minutes = int((time_delta.total_seconds() % 3600) // 60)
        time_remaining = f"{hours:02d}:{minutes:02d}:00"

        return templates.TemplateResponse("download_success.html", {
            "request": request,
            "cert_id": cert_id,
            "common_name": common_name,
            "server_id": server_id,
            "serial_number": cert_data['serial_number'],
            "valid_from": cert_data['not_valid_before'].strftime("%Y-%m-%d %H:%M:%S UTC"),
            "expires": cert_data['not_valid_after'].strftime("%Y-%m-%d %H:%M:%S UTC"),
            "expires_iso": cert_data['not_valid_after'].isoformat(),
            "fingerprint": cert_data['fingerprint_sha256'],
            "time_remaining": time_remaining,
            "p12_password": p12_password
        })

    except Exception as e:
        logger.error(f"Failed to issue certificate from UI: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to issue certificate: {str(e)}"
        )


@app.get("/ui/download/{cert_id}/pem")
async def download_cert_pem(cert_id: str):
    """Download certificate in PEM format."""
    cert_file = TEMP_CERT_STORAGE / cert_id / "cert.pem"
    if not cert_file.exists():
        raise HTTPException(status_code=404, detail="Certificate not found")

    return Response(
        content=cert_file.read_bytes(),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename=client-cert-{cert_id}.pem"}
    )


@app.get("/ui/download/{cert_id}/key")
async def download_cert_key(cert_id: str):
    """Download private key in PEM format."""
    key_file = TEMP_CERT_STORAGE / cert_id / "key.pem"
    if not key_file.exists():
        raise HTTPException(status_code=404, detail="Private key not found")

    return Response(
        content=key_file.read_bytes(),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename=client-key-{cert_id}.pem"}
    )


@app.get("/ui/download/{cert_id}/ca-chain")
async def download_ca_chain(cert_id: str):
    """Download CA certificate chain."""
    ca_file = TEMP_CERT_STORAGE / cert_id / "ca-chain.pem"
    if not ca_file.exists():
        raise HTTPException(status_code=404, detail="CA chain not found")

    return Response(
        content=ca_file.read_bytes(),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename=ca-chain-{cert_id}.pem"}
    )


@app.get("/ui/download/{cert_id}/bundle")
async def download_bundle(cert_id: str):
    """Download complete bundle (cert + key + CA chain)."""
    temp_dir = TEMP_CERT_STORAGE / cert_id
    cert_file = temp_dir / "cert.pem"
    key_file = temp_dir / "key.pem"
    ca_file = temp_dir / "ca-chain.pem"

    if not all([cert_file.exists(), key_file.exists(), ca_file.exists()]):
        raise HTTPException(status_code=404, detail="Certificate files not found")

    bundle = format_converter.create_bundle(
        cert_pem=cert_file.read_bytes(),
        key_pem=key_file.read_bytes(),
        ca_chain_pem=ca_file.read_bytes()
    )

    return Response(
        content=bundle,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename=client-bundle-{cert_id}.pem"}
    )


@app.get("/ui/download/{cert_id}/p12")
async def download_p12(cert_id: str):
    """Download certificate in PKCS#12 format (.p12)."""
    temp_dir = TEMP_CERT_STORAGE / cert_id
    cert_file = temp_dir / "cert.pem"
    key_file = temp_dir / "key.pem"
    ca_file = temp_dir / "ca-chain.pem"
    password_file = temp_dir / "p12_password.txt"

    if not all([cert_file.exists(), key_file.exists(), ca_file.exists()]):
        raise HTTPException(status_code=404, detail="Certificate files not found")

    # Read the password that was generated during certificate issuance
    password = password_file.read_text() if password_file.exists() else None

    p12_data = format_converter.pem_to_pkcs12(
        cert_pem=cert_file.read_bytes(),
        key_pem=key_file.read_bytes(),
        ca_chain_pem=ca_file.read_bytes(),
        password=password.encode() if password else None,
        friendly_name=f"AceIoT Client {cert_id}".encode()
    )

    return Response(
        content=p12_data,
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f"attachment; filename=client-{cert_id}.p12"}
    )


@app.get("/ui/download/{cert_id}/der")
async def download_der(cert_id: str):
    """Download certificate in DER format."""
    cert_file = TEMP_CERT_STORAGE / cert_id / "cert.pem"
    if not cert_file.exists():
        raise HTTPException(status_code=404, detail="Certificate not found")

    der_data = format_converter.pem_to_der(cert_file.read_bytes())

    return Response(
        content=der_data,
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": f"attachment; filename=client-{cert_id}.der"}
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
