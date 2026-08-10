from typing import Any

from pydantic import BaseModel


class RegistrationRequest(BaseModel):
    agent_id: str
    join_token: str

class CertificateRequest(BaseModel):
    agent_id: str
    public_key_pem: str
    attestation_data: dict[str, Any]

class CertificateResponse(BaseModel):
    agent_id: str
    spiffe_id: str
    certificate_pem: str
    serial_number: int
    expires_in_seconds: int

class RevocationRequest(BaseModel):
    serial_number: int
