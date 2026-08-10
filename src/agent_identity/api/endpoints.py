from datetime import UTC, datetime, timedelta

import bcrypt
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import PlainTextResponse

from agent_identity.ca.cert_authority import ca_instance
from agent_identity.models.agent import CertificateRequest, CertificateResponse, RegistrationRequest, RevocationRequest
from agent_identity.storage.pg_adapter import PostgresAdapter

router = APIRouter()
logger = structlog.get_logger()
db = PostgresAdapter()

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_workload(req: RegistrationRequest) -> dict[str, str]:
    hashed = bcrypt.hashpw(req.join_token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    await db.register_workload(req.agent_id, hashed)
    logger.info("Workload registered", agent_id=req.agent_id)
    return {"message": f"Workload {req.agent_id} successfully registered."}

@router.get("/trust-bundle", response_class=PlainTextResponse)
async def get_trust_bundle() -> str:
    import typing
    return typing.cast(str, ca_instance.certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

@router.post("/svid/issue", response_model=CertificateResponse)
async def issue_svid(req: CertificateRequest) -> CertificateResponse:
    join_token = req.attestation_data.get("join_token")
    if not join_token:
        raise HTTPException(status_code=401, detail="Missing join_token in attestation_data")

    # 1. Attest against DB
    hashed = await db.get_join_token_hash(req.agent_id)
    if not hashed or not bcrypt.checkpw(join_token.encode('utf-8'), hashed.encode('utf-8')):
        logger.warning("Agent attestation failed", agent_id=req.agent_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Attestation failed. Invalid join token."
        )

    # 2. Parse the public key
    try:
        public_key = serialization.load_pem_public_key(req.public_key_pem.encode('utf-8'))
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Only RSA keys are supported")
    except Exception as e:
        logger.error("Failed to parse public key", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid public key format."
        ) from e

    # 3. Issue the X509 SVID
    cert, cert_bytes = ca_instance.issue_workload_certificate(req.agent_id, public_key)
    
    # 4. Record to DB
    expires_at = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    await db.record_certificate(cert.serial_number, req.agent_id, expires_at)

    logger.info("SVID issued", agent_id=req.agent_id, serial=cert.serial_number)

    return CertificateResponse(
        agent_id=req.agent_id,
        spiffe_id=f"spiffe://{ca_instance.domain}/agent/{req.agent_id}",
        certificate_pem=cert_bytes.decode('utf-8'),
        serial_number=cert.serial_number,
        expires_in_seconds=3600
    )

@router.post("/svid/revoke")
async def revoke_svid(req: RevocationRequest) -> dict[str, str]:
    success = await db.revoke_certificate(req.serial_number)
    if not success:
        raise HTTPException(status_code=404, detail="Certificate not found or already revoked")
    logger.info("SVID revoked", serial=req.serial_number)
    return {"message": "Certificate successfully revoked."}
