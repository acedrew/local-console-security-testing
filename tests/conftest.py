"""Pytest configuration and shared fixtures for PKI testing."""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from typing import Generator


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test artifacts."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def ca_config(temp_dir: Path) -> dict:
    """Provide CA configuration for testing."""
    return {
        "ca_dir": temp_dir / "ca",
        "root_ca": {
            "common_name": "Test Root CA",
            "country": "US",
            "state": "TestState",
            "locality": "TestCity",
            "organization": "TestOrg",
            "organizational_unit": "TestOU",
            "validity_days": 3650,
        },
        "intermediate_ca": {
            "common_name": "Test Intermediate CA",
            "validity_days": 1825,
        },
        "server_cert": {
            "validity_days": 365,
        },
    }


@pytest.fixture
def cert_config() -> dict:
    """Provide certificate configuration for testing."""
    return {
        "ttl": 365,  # days
        "key_size": 2048,
        "hash_algorithm": "sha256",
    }


@pytest.fixture(autouse=True)
def cleanup_test_artifacts(temp_dir: Path):
    """Automatically cleanup test artifacts after each test."""
    yield
    # Cleanup happens via temp_dir fixture


@pytest.fixture
def mock_timestamp():
    """Provide a consistent timestamp for testing."""
    return datetime(2025, 1, 1, 0, 0, 0)


@pytest.fixture
def expired_timestamp():
    """Provide an expired timestamp for testing."""
    return datetime(2023, 1, 1, 0, 0, 0)


@pytest.fixture
def future_timestamp():
    """Provide a future timestamp for testing."""
    return datetime(2026, 1, 1, 0, 0, 0)
