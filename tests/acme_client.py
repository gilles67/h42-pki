"""A minimal ACME client for the integration tests (RFC 8555), on ``tests.acme_jws``."""

import base64
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from httpx import AsyncClient, Response

from tests.acme_jws import PrivateKey, jws

JOSE = {"Content-Type": "application/jose+json"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def csr_der(
    key: ec.EllipticCurvePrivateKey,
    names: list[str],
    *,
    common_name: str | None = None,
    ips: list[str] = (),  # type: ignore[assignment]
) -> bytes:
    import ipaddress

    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name else [])
    )
    general: list[x509.GeneralName] = [x509.DNSName(n) for n in names]
    general += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    if general:
        builder = builder.add_extension(x509.SubjectAlternativeName(general), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


@dataclass
class AcmeClient:
    http: AsyncClient
    key: PrivateKey
    directory_url: str = "https://localhost:8443/acme/directory"
    directory: dict[str, Any] = field(default_factory=dict)
    kid: str | None = None
    nonce: str | None = None

    async def load(self) -> dict[str, Any]:
        response = await self.http.get(self.directory_url)
        assert response.status_code == 200, response.text
        self.directory = response.json()
        return self.directory

    async def new_nonce(self) -> str:
        if not self.directory:
            await self.load()
        response = await self.http.head(self.directory["newNonce"])
        assert response.status_code == 200
        return response.headers["Replay-Nonce"]

    async def post(
        self,
        url: str,
        payload: Any = None,
        *,
        use_jwk: bool = False,
        key: PrivateKey | None = None,
        nonce: str | None = None,
        extra: dict[str, Any] | None = None,
        content_type: str = "application/jose+json",
    ) -> Response:
        """A signed POST (payload None: POST-as-GET); keeps the Replay-Nonce of the answer."""
        nonce = nonce or self.nonce or await self.new_nonce()
        self.nonce = None
        body = jws(
            key or self.key,
            payload,
            url=url,
            nonce=nonce,
            kid=None if use_jwk else self.kid,
            extra=extra,
        )
        response = await self.http.post(url, content=body, headers={"Content-Type": content_type})
        self.nonce = response.headers.get("Replay-Nonce")
        return response

    async def register(self, **payload: Any) -> Response:
        if not self.directory:
            await self.load()
        response = await self.post(
            self.directory["newAccount"], {"termsOfServiceAgreed": True, **payload}, use_jwk=True
        )
        if response.status_code in (200, 201):
            self.kid = response.headers["Location"]
        return response

    async def order(self, *identifiers: str, kind: str = "dns") -> Response:
        return await self.post(
            self.directory["newOrder"],
            {"identifiers": [{"type": kind, "value": value} for value in identifiers]},
        )

    async def get(self, url: str) -> Response:
        return await self.post(url)
