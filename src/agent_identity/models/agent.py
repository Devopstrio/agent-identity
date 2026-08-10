from typing import Any

from pydantic import BaseModel


class CertificateRequest(BaseModel):
    agent_id: str
    public_key_pem: str  # PEM encoded public key
    attestation_data: dict[str, Any]

class CertificateResponse(BaseModel):
    agent_id: str
    spiffe_id: str
    certificate_pem: str
    expires_in_seconds: int
