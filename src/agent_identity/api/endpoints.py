import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, HTTPException, status

from agent_identity.ca.cert_authority import ca_instance
from agent_identity.models.agent import CertificateRequest, CertificateResponse

router = APIRouter()
logger = structlog.get_logger()

@router.post("/svid/issue", response_model=CertificateResponse)
async def issue_svid(req: CertificateRequest) -> CertificateResponse:
    # 1. Attest the node (Mock logic for this demo)
    if req.attestation_data.get("join_token") != "secure_join_token":
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
        )

    # 3. Issue the X509 SVID
    cert_bytes = ca_instance.issue_workload_certificate(req.agent_id, public_key)

    logger.info("SVID issued", agent_id=req.agent_id)

    return CertificateResponse(
        agent_id=req.agent_id,
        spiffe_id=f"spiffe://{ca_instance.domain}/agent/{req.agent_id}",
        certificate_pem=cert_bytes.decode('utf-8'),
        expires_in_seconds=3600
    )
