from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertificateAuthority:
    def __init__(self, domain: str = "devopstrio.local"):
        self.domain = domain
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DevopsTrio"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"CA {domain}"),
        ])
        self.certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(UTC)
        ).not_valid_after(
            datetime.now(UTC) + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(self.private_key, hashes.SHA256())

    def issue_workload_certificate(self, agent_id: str, public_key: rsa.RSAPublicKey) -> tuple[x509.Certificate, bytes]:
        spiffe_id = f"spiffe://{self.domain}/agent/{agent_id}"
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DevopsTrio"),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(UTC)
        ).not_valid_after(
            datetime.now(UTC) + timedelta(hours=1)  # Short lived!
        ).add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        ).sign(self.private_key, hashes.SHA256())
        
        return cert, cert.public_bytes(serialization.Encoding.PEM)

# Global CA instance for simplicity
ca_instance = CertificateAuthority()
