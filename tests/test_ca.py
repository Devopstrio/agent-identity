from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from agent_identity.main import app

client = TestClient(app)

def test_health_check() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_issue_svid() -> None:
    # Generate a dummy RSA key for the test workload
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    response = client.post("/v1/identity/svid/issue", json={
        "agent_id": "test-agent-pod",
        "public_key_pem": public_key_pem,
        "attestation_data": {
            "join_token": "secure_join_token"
        }
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["spiffe_id"] == "spiffe://devopstrio.local/agent/test-agent-pod"
    assert "BEGIN CERTIFICATE" in data["certificate_pem"]

def test_issue_svid_failed_attestation() -> None:
    response = client.post("/v1/identity/svid/issue", json={
        "agent_id": "test-agent-pod",
        "public_key_pem": "invalid_key",
        "attestation_data": {
            "join_token": "wrong_token"
        }
    })
    
    assert response.status_code == 401
