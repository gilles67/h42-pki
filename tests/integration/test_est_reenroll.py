"""EST simplereenroll (RFC 7030 section 4.2.2) and csrattrs (section 4.5), ADR-0018."""

import base64
from datetime import timedelta

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, NameOID
from httpx import AsyncClient, Response

from h42pki.core.keys import KeyAlgorithm
from h42pki.keystore import KeyStore
from h42pki.models import AuditLog, Certificate, CertificateStatus
from h42pki.services.est import EstService
from h42pki.services.revocation import RevocationService
from tests.conftest import IssueFactory
from tests.integration.test_est import (
    EST,
    KeyFor,
    basic,
    certificates,
    client_cert_header,
    csr_body,
    est,  # noqa: F401 - fixture
    trusted_proxy,  # noqa: F401 - fixture
)
from tests.unit.core.test_est import _read_oids
from tests.x509_helpers import csr_pem, make_csr, name

pytestmark = pytest.mark.usefixtures("est", "trusted_proxy")


async def device(issue: IssueFactory, key_for: KeyFor) -> x509.Certificate:
    """A tls_client certificate (CN + DNS SAN), the credential of the re-enrolment."""
    key = key_for(KeyAlgorithm.EC_P256)
    csr = make_csr(key, name(CN="device-1"), sans=["dns:device-1.test"])
    request = await issue("tls_client", csr_pem(csr))
    return x509.load_der_x509_certificate((await Certificate.get(id=request.certificate_id)).der)


def reenrol_body(
    key_for: KeyFor,
    *,
    cn: str = "device-1",
    sans: tuple[str, ...] = ("dns:device-1.test",),
    algorithm: KeyAlgorithm = KeyAlgorithm.EC_P384,
    attributes: tuple[tuple[x509.ObjectIdentifier, bytes], ...] = (),
) -> bytes:
    from tests.x509_helpers import general_name

    key = key_for(algorithm)
    builder = x509.CertificateSigningRequestBuilder().subject_name(name(CN=cn))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([general_name(san) for san in sans]), critical=False
        )
    for oid, value in attributes:
        builder = builder.add_attribute(oid, value)
    csr = builder.sign(key, hashes.SHA256())
    return base64.b64encode(csr.public_bytes(serialization.Encoding.DER))


async def reenrol(
    client: AsyncClient, body: bytes, *, label: str | None = None, **headers: str
) -> Response:
    path = f"{EST}/{label}/simplereenroll" if label else f"{EST}/simplereenroll"
    return await client.post(
        path, content=body, headers={"Content-Type": "application/pkcs10", **headers}
    )


async def test_reenrol_with_a_new_key(
    client: AsyncClient, issue: IssueFactory, key_for: KeyFor
) -> None:
    current = await device(issue, key_for)

    [renewed] = certificates(
        await reenrol(client, reenrol_body(key_for), **client_cert_header(current))
    )

    assert renewed.subject == current.subject and renewed.serial_number != current.serial_number
    assert renewed.public_key() != current.public_key()
    eku = renewed.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == list(
        current.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    )
    entry = await AuditLog.get(action="est.reenroll")
    assert entry.details["previous_serial_hex"] == format(current.serial_number, "x")
    old = await Certificate.get(sha256_fingerprint=current.fingerprint(hashes.SHA256()).hex())
    assert old.status is CertificateStatus.VALID  # not revoked automatically


async def test_reenrol_with_the_same_key(
    client: AsyncClient, issue: IssueFactory, key_for: KeyFor
) -> None:
    current = await device(issue, key_for)
    body = reenrol_body(key_for, algorithm=KeyAlgorithm.EC_P256)  # the key of the current one

    [renewed] = certificates(
        await reenrol(client, body, label="tls_client", **client_cert_header(current))
    )

    assert renewed.public_key() == current.public_key()


@pytest.mark.parametrize(
    "changes",
    [
        {"cn": "device-2"},
        {"sans": ("dns:device-2.test",)},
        {"sans": ("dns:device-1.test", "dns:extra.test")},
        {"sans": ()},
        {"attributes": ((x509.ObjectIdentifier("1.3.6.1.5.5.7.7.36"), b"other"),)},
    ],
    ids=["subject", "san", "more sans", "no san", "ChangeSubjectName"],
)
async def test_identity_must_not_change(
    client: AsyncClient, issue: IssueFactory, key_for: KeyFor, changes: dict[str, object]
) -> None:
    current = await device(issue, key_for)

    response = await reenrol(
        client, reenrol_body(key_for, **changes), **client_cert_header(current)
    )  # type: ignore[arg-type]

    assert response.status_code == 400, response.text
    assert response.headers["content-type"].startswith("text/plain")


async def test_label_must_be_the_profile_of_the_certificate(
    client: AsyncClient, issue: IssueFactory, key_for: KeyFor
) -> None:
    current = await device(issue, key_for)

    other = await reenrol(
        client, reenrol_body(key_for), label="device", **client_cert_header(current)
    )
    unknown = await reenrol(
        client, reenrol_body(key_for), label="nope", **client_cert_header(current)
    )

    assert other.status_code == 400 and "profile 'tls_client'" in other.text
    assert unknown.status_code == 404


async def test_basic_alone_is_not_enough(client: AsyncClient, key_for: KeyFor) -> None:
    response = await reenrol(client, reenrol_body(key_for), **basic())

    assert response.status_code == 401
    assert response.text == "a valid client certificate issued by this CA is required\n"


async def test_revoked_or_expired_certificate(
    client: AsyncClient, issue: IssueFactory, key_for: KeyFor, keystore: KeyStore
) -> None:
    current = await device(issue, key_for)
    with time_machine.travel(current.not_valid_after_utc + timedelta(seconds=1), tick=False):
        expired = await reenrol(client, reenrol_body(key_for), **client_cert_header(current))
    record = await Certificate.get(sha256_fingerprint=current.fingerprint(hashes.SHA256()).hex())
    await RevocationService(keystore).revoke(record.id, reason="superseded", actor="cli")
    revoked = await reenrol(client, reenrol_body(key_for), **client_cert_header(current))

    assert (expired.status_code, revoked.status_code) == (401, 401)


async def test_server_certificate_cannot_authenticate(client: AsyncClient, key_for: KeyFor) -> None:
    """Like OpenSSL in the TLS handshake: an EKU without clientAuth is refused."""
    [server] = certificates(
        await client.post(
            f"{EST}/tls_server/simpleenroll",
            content=csr_body(key_for, "www.example.test"),
            headers={"Content-Type": "application/pkcs10", **basic()},
        )
    )

    response = await reenrol(
        client,
        reenrol_body(key_for, cn="www.example.test", sans=("dns:www.example.test",)),
        **client_cert_header(server),
    )

    assert response.status_code == 401


# --- csrattrs ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("tls_server", [ExtensionOID.SUBJECT_ALTERNATIVE_NAME]),
        ("tls_client", [NameOID.COMMON_NAME]),
        ("sub_ca", [NameOID.COMMON_NAME]),
    ],
)
async def test_csrattrs(
    client: AsyncClient, label: str, expected: list[x509.ObjectIdentifier]
) -> None:
    response = await client.get(f"{EST}/{label}/csrattrs")  # no authentication

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/csrattrs"
    assert response.headers["content-transfer-encoding"] == "base64"
    oids = _read_oids(base64.b64decode(response.content))
    assert oids == [oid.dotted_string for oid in expected]


async def test_csrattrs_204_when_nothing_is_required(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def nothing(profile: str) -> list[x509.ObjectIdentifier]:
        return []

    monkeypatch.setattr(EstService, "csr_attributes", staticmethod(nothing))

    response = await client.get(f"{EST}/tls_server/csrattrs")

    assert response.status_code == 204 and response.content == b""


async def test_csrattrs_unknown_label(client: AsyncClient) -> None:
    assert (await client.get(f"{EST}/nope/csrattrs")).status_code == 404
