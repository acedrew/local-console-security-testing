"""Data models for PKI service."""

from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr


class CertificateRequest(BaseModel):
    """Request model for client certificate issuance."""

    common_name: str = Field(..., description="Common name for the certificate")
    organization: str = Field(..., description="Organization name")
    email: Optional[EmailStr] = Field(None, description="Email address")
    server_id: str = Field(..., description="Server ID for intermediate CA")
    validity_hours: int = Field(default=1, ge=1, le=87600, description="Certificate validity in hours (max 10 years)")
    san_dns_names: Optional[list[str]] = Field(None, description="Subject Alternative Names - DNS names")
    san_ip_addresses: Optional[list[str]] = Field(None, description="Subject Alternative Names - IP addresses")


class IntermediateCARequest(BaseModel):
    """Request model for intermediate CA creation."""

    server_id: str = Field(..., description="Unique server identifier")
    organization: str = Field(..., description="Organization name")
    common_name: Optional[str] = Field(None, description="Custom common name (defaults to server_id)")
    validity_days: int = Field(default=365, ge=1, le=3650, description="CA validity in days")


class CertificateResponse(BaseModel):
    """Response model for certificate operations."""

    certificate: str = Field(..., description="PEM-encoded certificate")
    private_key: str = Field(..., description="PEM-encoded private key")
    ca_chain: str = Field(..., description="PEM-encoded CA certificate chain")
    serial_number: int = Field(..., description="Certificate serial number")
    not_valid_before: datetime = Field(..., description="Certificate start date")
    not_valid_after: datetime = Field(..., description="Certificate expiration date")
    fingerprint_sha256: str = Field(..., description="SHA-256 fingerprint")


class IntermediateCAResponse(BaseModel):
    """Response model for intermediate CA creation."""

    server_id: str = Field(..., description="Server identifier")
    certificate: str = Field(..., description="PEM-encoded intermediate CA certificate")
    ca_chain: str = Field(..., description="PEM-encoded CA chain (intermediate + root)")
    serial_number: int = Field(..., description="Certificate serial number")
    not_valid_before: datetime = Field(..., description="Certificate start date")
    not_valid_after: datetime = Field(..., description="Certificate expiration date")
    fingerprint_sha256: str = Field(..., description="SHA-256 fingerprint")


class CertificateInfo(BaseModel):
    """Certificate information model."""

    subject: dict = Field(..., description="Certificate subject information")
    issuer: dict = Field(..., description="Certificate issuer information")
    serial_number: int = Field(..., description="Certificate serial number")
    not_valid_before: str = Field(..., description="Certificate start date")
    not_valid_after: str = Field(..., description="Certificate expiration date")
    fingerprint_sha256: str = Field(..., description="SHA-256 fingerprint")
    valid: bool = Field(..., description="Whether certificate is currently valid")


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str = Field(..., description="Service status")
    root_ca_initialized: bool = Field(..., description="Whether root CA is initialized")
    intermediate_cas: int = Field(..., description="Number of intermediate CAs")
    timestamp: datetime = Field(..., description="Current server time")


class ErrorResponse(BaseModel):
    """Error response model."""

    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
