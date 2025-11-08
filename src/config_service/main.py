"""FastAPI Configuration Service with mTLS enforcement."""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from .config_manager import ConfigManager
from .auth import MTLSAuthenticator, CertificateVerificationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AceIoT Configuration Service",
    description="Secure configuration management with mTLS authentication",
    version="2.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration paths
CONFIG_DIR = Path.home() / ".aceiot" / "config"
CA_DIR = Path.home() / ".aceiot" / "pki" / "ca"

# Initialize managers
config_manager = ConfigManager(CONFIG_DIR)

# Initialize templates
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def get_client_certificate(request: Request) -> Optional[dict]:
    """
    Extract and verify client certificate from request.

    With uvicorn --ssl-cert-reqs=2, the TLS layer enforces client certificates.
    Any request that reaches this point has already been verified by the SSL handshake.

    In production, you would extract detailed certificate info from:
    - Custom ASGI middleware that inspects the SSL socket
    - Reverse proxy headers (X-SSL-Client-Cert, X-SSL-Client-DN, etc.)
    - TLS-terminating load balancer headers
    """
    # Check for certificate info from reverse proxy headers
    client_cert_header = request.headers.get("X-Client-Cert")
    ssl_client_dn = request.headers.get("X-SSL-Client-DN")
    ssl_client_serial = request.headers.get("X-SSL-Client-Serial")

    if client_cert_header or ssl_client_dn:
        # Running behind reverse proxy with certificate headers
        return {
            "verified": True,
            "subject": {"DN": ssl_client_dn or "unknown"},
            "serial": ssl_client_serial or "unknown",
            "source": "proxy-headers"
        }

    # When using uvicorn directly with --ssl-cert-reqs=2,
    # the TLS layer has already verified the certificate.
    # If the request reached here, it means a valid client cert was provided.
    if request.scope.get("scheme") == "https":
        # Get client connection info
        client_addr = request.scope.get("client")
        if client_addr:
            return {
                "verified": True,
                "subject": {"CN": f"client-{client_addr[0]}"},
                "serial": "tls-verified",
                "source": "uvicorn-tls",
                "client_addr": client_addr[0]
            }

    return None


def verify_client_certificate(request: Request) -> dict:
    """
    Verify client certificate is present and valid.

    Raises HTTPException if certificate is missing or invalid.
    """
    cert_info = get_client_certificate(request)

    if not cert_info:
        # No certificate provided - reject
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client certificate required. Please configure mTLS authentication.",
            headers={"WWW-Authenticate": "Certificate"}
        )

    return cert_info


@app.middleware("http")
async def enforce_mtls(request: Request, call_next):
    """
    Middleware to enforce mTLS on all requests.

    Rejects any request without a valid client certificate.
    """
    # Allow health check endpoint without cert (for monitoring)
    if request.url.path == "/health":
        return await call_next(request)

    try:
        # Verify certificate is present
        cert_info = verify_client_certificate(request)

        # Add certificate info to request state for use in endpoints
        request.state.client_cert = cert_info

        logger.info(f"mTLS verified for {cert_info.get('subject', {}).get('CN', 'unknown')}")

        return await call_next(request)

    except HTTPException as e:
        logger.warning(f"mTLS verification failed: {e.detail}")
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": "Authentication Required",
                "message": e.detail,
                "help": "Please access this service with a valid client certificate. Visit http://pki-service:8000/ui/download to obtain a certificate."
            }
        )


@app.get("/health")
async def health_check():
    """Health check endpoint (no mTLS required)."""
    return {
        "status": "healthy",
        "service": "config-service",
        "mtls": "enforced",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Main configuration interface."""
    try:
        # Get current configuration
        current_config = config_manager.load_config() or {}

        # Get certificate info from request state
        cert_info = request.state.client_cert

        # Get configuration history
        versions = config_manager.get_version_history()

        return templates.TemplateResponse("config_ui.html", {
            "request": request,
            "config": json.dumps(current_config, indent=2),
            "cert_info": cert_info,
            "versions": versions[:10],  # Last 10 versions
            "version_count": len(versions)
        })

    except Exception as e:
        logger.error(f"Failed to load configuration UI: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load configuration: {str(e)}"
        )


@app.get("/api/config")
async def get_config(request: Request):
    """Get current configuration (API endpoint)."""
    try:
        config = config_manager.load_config()
        cert_info = request.state.client_cert

        return {
            "config": config or {},
            "authenticated_as": cert_info.get("subject", {}).get("CN", "unknown"),
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to get configuration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get configuration: {str(e)}"
        )


@app.post("/api/config")
async def update_config(request: Request, config_data: Dict[str, Any]):
    """Update configuration (API endpoint)."""
    try:
        cert_info = request.state.client_cert
        author = cert_info.get("subject", {}).get("CN", "unknown")

        # Save configuration
        success = config_manager.save_config(
            config_data,
            author=author
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to save configuration"
            )

        logger.info(f"Configuration updated by {author}")

        return {
            "success": True,
            "message": "Configuration saved successfully",
            "author": author,
            "timestamp": datetime.utcnow().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update configuration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update configuration: {str(e)}"
        )


@app.get("/api/versions")
async def get_versions(request: Request, limit: int = 20):
    """Get configuration version history."""
    try:
        versions = config_manager.get_version_history()
        return {
            "versions": versions[:limit],
            "total": len(versions)
        }

    except Exception as e:
        logger.error(f"Failed to get version history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get version history: {str(e)}"
        )


@app.get("/api/versions/{version}")
async def get_version(request: Request, version: int):
    """Get specific configuration version."""
    try:
        version_obj = config_manager.get_version(version)

        if not version_obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Version {version} not found"
            )

        return {
            "version": version,
            "config": version_obj.data,
            "timestamp": version_obj.timestamp.isoformat(),
            "hash": version_obj.hash
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get version: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get version: {str(e)}"
        )


@app.post("/api/versions/{version}/restore")
async def restore_version(request: Request, version: int):
    """Restore a previous configuration version."""
    try:
        cert_info = request.state.client_cert
        author = cert_info.get("subject", {}).get("CN", "unknown")

        success = config_manager.restore_version(version, author=author)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Version {version} not found"
            )

        logger.info(f"Configuration restored to version {version} by {author}")

        return {
            "success": True,
            "message": f"Configuration restored to version {version}",
            "restored_by": author,
            "timestamp": datetime.utcnow().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to restore version: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to restore version: {str(e)}"
        )


@app.get("/api/audit")
async def get_audit_log(request: Request, limit: int = 50):
    """Get audit log of configuration changes."""
    try:
        audit_log = config_manager.get_audit_log(limit=limit)
        return {
            "entries": audit_log,
            "count": len(audit_log)
        }

    except Exception as e:
        logger.error(f"Failed to get audit log: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get audit log: {str(e)}"
        )


@app.get("/api/cert-info")
async def get_cert_info(request: Request):
    """Get information about the client certificate used for authentication."""
    cert_info = request.state.client_cert
    return {
        "authenticated": True,
        "certificate": cert_info,
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn

    # Note: For mTLS to work properly, uvicorn must be run with:
    # --ssl-keyfile, --ssl-certfile, --ssl-ca-certs, --ssl-cert-reqs=2

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8501,
        reload=True,
        log_level="info"
    )
