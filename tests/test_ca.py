from typing import Any
from unittest.mock import AsyncMock, patch

import bcrypt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from agent_identity.main import app

client = TestClient(app)

def test_health_check() -> None:
    response = client.get("/health")
    assert response.status_code == 200

def test_get_trust_bundle() -> None:
    response = client.get("/v1/identity/trust-bundle")
    assert response.status_code == 200
    assert "BEGIN CERTIFICATE" in response.text

@pytest.mark.asyncio
@patch("agent_identity.api.endpoints.db")
async def test_register_workload(mock_db: Any) -> None:
    mock_db.register_workload = AsyncMock()
    response = client.post("/v1/identity/register", json={
        "agent_id": "test-agent",
        "join_token": "secret"
    })
    assert response.status_code == 201
    mock_db.register_workload.assert_called_once()

@pytest.mark.asyncio
@patch("agent_identity.api.endpoints.db")
async def test_issue_svid_success(mock_db: Any) -> None:
    # Setup mock
    hashed = bcrypt.hashpw(b"secret", bcrypt.gensalt()).decode("utf-8")
    mock_db.get_join_token_hash = AsyncMock(return_value=hashed)
    mock_db.record_certificate = AsyncMock()

    # Generate key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    response = client.post("/v1/identity/svid/issue", json={
        "agent_id": "test-agent",
        "public_key_pem": public_key_pem,
        "attestation_data": {"join_token": "secret"}
    })
    assert response.status_code == 200
    assert "certificate_pem" in response.json()
    mock_db.record_certificate.assert_called_once()

@pytest.mark.asyncio
@patch("agent_identity.api.endpoints.db")
async def test_revoke_svid(mock_db: Any) -> None:
    mock_db.revoke_certificate = AsyncMock(return_value=True)
    response = client.post("/v1/identity/svid/revoke", json={"serial_number": 12345})
    assert response.status_code == 200
    mock_db.revoke_certificate.assert_called_once_with(12345)
