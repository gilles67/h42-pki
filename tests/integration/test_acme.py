"""ACME (RFC 8555, ADR-0020): directory, nonces, accounts, orders, http-01, finalize, chain."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from httpx import AsyncClient

from h42pki.core.acme.errors import AcmeError
from h42pki.core.profiles import BUILTIN_PROFILES
from h42pki.logs import SERVER_LOGGERS
from h42pki.models import (
    AcmeChallenge,
    AcmeNonce,
    AuditLog,
    CertificateRequest,
    ChallengeStatus,
    Channel,
)
from h42pki.services.acme import validation as validation_module
from h42pki.services.acme.nonces import NonceService
from h42pki.services.acme.validation import AcmeValidation
from h42pki.services.settings import SettingsService
from tests.acme_client import AcmeClient, b64url, csr_der
from tests.conftest import RootFactory

BASE = "https://localhost:8443"
PROBLEM = "urn:ietf:params:acme:error:"


class FakeChecker:
    """Stands for the network: records the http-01 checks, fails while ``failures`` > 0."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.dns_calls: list[tuple[str, str, list[str]]] = []
        self.failures = 0

    async def http01(self, host: str, token: str, expected: str) -> None:
        self.calls.append((host, token, expected))
        if self.failures:
            self.failures -= 1
            raise AcmeError("connection", f"cannot reach {host}")

    async def dns01(self, domain: str, expected: str, resolvers: Any) -> None:
        self.dns_calls.append((domain, expected, list(resolvers)))
        if self.failures:
            self.failures -= 1
            raise AcmeError("dns", f"no TXT record _acme-challenge.{domain}")


@pytest.fixture
def checker(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> FakeChecker:
    fake = FakeChecker()
    app.state.acme_validation.checker = fake
    monkeypatch.setattr(validation_module, "RETRY_DELAYS_SECONDS", (0.0, 0.0))
    return fake


@pytest.fixture
async def acme(make_root: RootFactory, checker: FakeChecker) -> None:
    await make_root()
    await SettingsService().set("acme.enabled", True, actor="cli")


@pytest.fixture
def account_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
async def acme_client(acme: None, client: AsyncClient, account_key: Any) -> AcmeClient:
    acme_client = AcmeClient(client, account_key)
    response = await acme_client.register(contact=["mailto:admin@example.test"])
    assert response.status_code == 201, response.text
    return acme_client


def http01(authz: dict[str, Any]) -> dict[str, Any]:
    [challenge] = [c for c in authz["challenges"] if c["type"] == "http-01"]
    return challenge


def problem(response: Any) -> str:
    assert response.headers["content-type"] == "application/problem+json", response.text
    assert "Replay-Nonce" in response.headers
    return str(response.json()["type"]).removeprefix(PROBLEM)


async def validate_all(
    acme_client: AcmeClient, app: FastAPI, order: dict[str, Any], kind: str = "http-01"
) -> None:
    for authz_url in order["authorizations"]:
        authz = (await acme_client.get(authz_url)).json()
        offered = {c["type"]: c for c in authz["challenges"]}
        challenge = offered.get(kind) or offered["dns-01"]  # a wildcard: dns-01 only
        response = await acme_client.post(challenge["url"], {})
        assert response.status_code == 200, response.text
        if response.json()["status"] == "processing":
            assert response.headers["Retry-After"] == "2"
        assert f'<{authz_url}>;rel="up"' in response.headers["link"]
    await app.state.acme_validation.drain()


async def issue(
    acme_client: AcmeClient, app: FastAPI, *names: str, ips: tuple[str, ...] = ()
) -> tuple[str, dict[str, Any], ec.EllipticCurvePrivateKey]:
    identifiers = [{"type": "dns", "value": n} for n in names]
    identifiers += [{"type": "ip", "value": ip} for ip in ips]
    created = await acme_client.post(
        acme_client.directory["newOrder"], {"identifiers": identifiers}
    )
    assert created.status_code == 201, created.text
    order_url = created.headers["Location"]
    await validate_all(acme_client, app, created.json())
    key = ec.generate_private_key(ec.SECP256R1())
    finalize = created.json()["finalize"]
    csr = csr_der(key, list(names), ips=list(ips))
    response = await acme_client.post(finalize, {"csr": b64url(csr)})
    assert response.status_code == 200, response.text
    return order_url, response.json(), key


# --- availability -----------------------------------------------------------------------------

ROUTES = [
    ("GET", "/acme/directory"),
    ("GET", "/acme/tls_server/directory"),
    ("HEAD", "/acme/new-nonce"),
    ("GET", "/acme/new-nonce"),
    ("POST", "/acme/new-account"),
    ("POST", "/acme/acct/00000000-0000-0000-0000-000000000000"),
    ("POST", "/acme/acct/00000000-0000-0000-0000-000000000000/orders"),
    ("POST", "/acme/new-order"),
    ("POST", "/acme/tls_server/new-order"),
    ("POST", "/acme/order/00000000-0000-0000-0000-000000000000"),
    ("POST", "/acme/order/00000000-0000-0000-0000-000000000000/finalize"),
    ("POST", "/acme/authz/00000000-0000-0000-0000-000000000000"),
    ("POST", "/acme/chall/00000000-0000-0000-0000-000000000000"),
    ("POST", "/acme/cert/00000000-0000-0000-0000-000000000000"),
]


@pytest.mark.parametrize(("method", "path"), ROUTES)
async def test_disabled_by_default(
    client: AsyncClient, make_root: RootFactory, method: str, path: str
) -> None:
    await make_root()

    response = await client.request(method, path, content=b"{}")

    assert response.status_code == 404
    assert "Replay-Nonce" not in response.headers


@pytest.mark.usefixtures("acme")
async def test_directory(client: AsyncClient) -> None:
    default = await client.get("/acme/directory")
    by_profile = await client.get("/acme/tls_client/directory")

    assert default.status_code == 200 and default.headers["cache-control"] == "no-store"
    assert default.json() == {
        "newNonce": f"{BASE}/acme/new-nonce",
        "newAccount": f"{BASE}/acme/new-account",
        "newOrder": f"{BASE}/acme/new-order",
        "revokeCert": f"{BASE}/acme/revoke-cert",
        "meta": {"externalAccountRequired": False, "profile": "tls_server"},
    }
    assert by_profile.json()["newOrder"] == f"{BASE}/acme/tls_client/new-order"
    assert by_profile.headers["link"] == f'<{BASE}/acme/tls_client/directory>;rel="index"'
    assert default.headers["Replay-Nonce"]


@pytest.mark.usefixtures("acme")
@pytest.mark.parametrize("label", ["service_tls", "scep_ra", "nope", "sub_ca-x"])
async def test_unknown_or_internal_profile(client: AsyncClient, label: str) -> None:
    assert (await client.get(f"/acme/{label}/directory")).status_code == 404


@pytest.mark.usefixtures("acme")
async def test_disabled_profile_and_default(client: AsyncClient) -> None:
    await SettingsService().set("issuance.disabled_profiles", ["tls_client"], actor="cli")
    await SettingsService().set("acme.default_profile", "", actor="cli")

    assert (await client.get("/acme/tls_client/directory")).status_code == 404
    assert (await client.get("/acme/directory")).status_code == 404
    assert (await client.get("/acme/device/directory")).status_code == 200


@pytest.mark.usefixtures("acme")
async def test_base_url_and_terms(client: AsyncClient) -> None:
    await SettingsService().set("acme.base_url", "https://pki.example.test", actor="cli")
    await SettingsService().set("acme.terms_of_service_url", "https://x.test/tos", actor="cli")

    document = (await client.get("/acme/directory", headers={"Host": "evil.test"})).json()

    assert document["newNonce"] == "https://pki.example.test/acme/new-nonce"
    assert document["meta"]["termsOfService"] == "https://x.test/tos"


@pytest.mark.usefixtures("acme")
async def test_new_nonce(client: AsyncClient) -> None:
    head = await client.head("/acme/new-nonce")
    get = await client.get("/acme/new-nonce")

    assert (head.status_code, get.status_code) == (200, 204)
    assert head.headers["Replay-Nonce"] != get.headers["Replay-Nonce"]
    assert await AcmeNonce.filter(value=head.headers["Replay-Nonce"]).exists()


# --- accounts ---------------------------------------------------------------------------------


async def test_account_creation_and_lookup(acme_client: AcmeClient) -> None:
    again = await acme_client.register()
    existing = await acme_client.post(
        acme_client.directory["newAccount"], {"onlyReturnExisting": True}, use_jwk=True
    )
    read = await acme_client.get(acme_client.kid or "")

    assert again.status_code == 200 and again.headers["Location"] == acme_client.kid
    assert existing.status_code == 200
    assert read.json()["contact"] == ["mailto:admin@example.test"]
    assert read.json()["status"] == "valid"
    assert read.json()["orders"] == f"{acme_client.kid}/orders"


@pytest.mark.usefixtures("acme")
async def test_only_return_existing_unknown(client: AsyncClient, account_key: Any) -> None:
    acme_client = AcmeClient(client, account_key)
    await acme_client.load()

    response = await acme_client.post(
        acme_client.directory["newAccount"], {"onlyReturnExisting": True}, use_jwk=True
    )

    assert problem(response) == "accountDoesNotExist"


@pytest.mark.usefixtures("acme")
@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({"contact": ["tel:+33123"]}, "unsupportedContact"),
        ({"contact": ["mailto:a@b.test,c@d.test"]}, "invalidContact"),
        ({"contact": "mailto:a@b.test"}, "malformed"),
    ],
)
async def test_invalid_contacts(
    client: AsyncClient, account_key: Any, payload: dict[str, Any], code: str
) -> None:
    acme_client = AcmeClient(client, account_key)

    assert problem(await acme_client.register(**payload)) == code


@pytest.mark.usefixtures("acme")
async def test_terms_of_service_must_be_agreed(client: AsyncClient, account_key: Any) -> None:
    await SettingsService().set("acme.terms_of_service_url", "https://x.test/tos", actor="cli")
    acme_client = AcmeClient(client, account_key)
    await acme_client.load()

    refused = await acme_client.post(acme_client.directory["newAccount"], {}, use_jwk=True)
    agreed = await acme_client.register()

    assert problem(refused) == "malformed" and agreed.status_code == 201
    assert agreed.json()["termsOfServiceAgreed"] is True


async def test_account_update_and_deactivation(acme_client: AcmeClient) -> None:
    kid = acme_client.kid or ""
    updated = await acme_client.post(kid, {"contact": ["mailto:new@example.test"]})
    deactivated = await acme_client.post(kid, {"status": "deactivated"})
    after = await acme_client.get(kid)

    assert updated.json()["contact"] == ["mailto:new@example.test"]
    assert deactivated.json()["status"] == "deactivated"
    assert problem(after) == "unauthorized" and after.status_code == 403
    actions = await AuditLog.filter(object_type="acme_account").values_list("action", flat=True)
    assert set(actions) == {"acme.account.create", "acme.account.update", "acme.account.deactivate"}


async def test_another_account_is_not_readable(
    acme_client: AcmeClient, client: AsyncClient
) -> None:
    other = AcmeClient(client, ec.generate_private_key(ec.SECP256R1()))
    await other.register()

    response = await other.get(acme_client.kid or "")

    assert problem(response) == "unauthorized"


# --- request authentication -------------------------------------------------------------------


async def test_nonce_is_single_use(acme_client: AcmeClient) -> None:
    nonce = await acme_client.new_nonce()
    first = await acme_client.post(acme_client.kid or "", nonce=nonce)
    replayed = await acme_client.post(acme_client.kid or "", nonce=nonce)
    unknown = await acme_client.post(acme_client.kid or "", nonce="bm9uY2U")

    assert first.status_code == 200
    assert problem(replayed) == "badNonce" and problem(unknown) == "badNonce"
    assert replayed.status_code == 400


async def test_nonce_expiry_and_purge(acme_client: AcmeClient) -> None:
    nonce = await acme_client.new_nonce()
    with time_machine.travel(datetime.now(UTC) + timedelta(minutes=61)):
        expired = await acme_client.post(acme_client.kid or "", nonce=nonce)
        purged = await NonceService.purge()

    assert problem(expired) == "badNonce"
    assert purged >= 1 and not await AcmeNonce.filter(value=nonce).exists()


async def test_url_must_be_the_request_url(acme_client: AcmeClient, client: AsyncClient) -> None:
    from tests.acme_jws import jws

    body = jws(
        acme_client.key, None, url=f"{BASE}/acme/elsewhere",
        nonce=await acme_client.new_nonce(), kid=acme_client.kid,
    )  # fmt: skip
    response = await client.post(
        acme_client.kid or "", content=body, headers={"Content-Type": "application/jose+json"}
    )

    assert problem(response) == "unauthorized"


async def test_signature_errors(acme_client: AcmeClient) -> None:
    kid = acme_client.kid or ""
    wrong_key = await acme_client.post(kid, key=ec.generate_private_key(ec.SECP256R1()))
    wrong_type = await acme_client.post(kid, content_type="application/json")
    jwk_on_kid_route = await acme_client.post(kid, use_jwk=True)
    unknown_kid = await acme_client.post(f"{BASE}/acme/acct/00000000-0000-0000-0000-000000000000")

    assert problem(wrong_key) == "malformed"
    assert wrong_type.status_code == 415 and problem(wrong_type) == "malformed"
    assert problem(jwk_on_kid_route) == "malformed"
    assert problem(unknown_kid) == "unauthorized"  # the kid is valid, not its account


async def test_unknown_kid(acme_client: AcmeClient) -> None:
    acme_client.kid = f"{BASE}/acme/acct/00000000-0000-0000-0000-000000000000"

    assert problem(await acme_client.get(acme_client.kid)) == "accountDoesNotExist"


# --- orders and http-01 -----------------------------------------------------------------------


async def test_order_to_certificate(
    acme_client: AcmeClient, app: FastAPI, checker: FakeChecker
) -> None:
    order_url, final, key = await issue(acme_client, app, "www.example.test", "api.example.test")
    certificate = await acme_client.get(final["certificate"])

    assert final["status"] == "valid"
    assert certificate.status_code == 200
    assert certificate.headers["content-type"] == "application/pem-certificate-chain"
    [leaf] = x509.load_pem_x509_certificates(certificate.content)  # issued by the root: no root
    names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sorted(names.get_values_for_type(x509.DNSName)) == [
        "api.example.test",
        "www.example.test",
    ]
    assert leaf.public_key() == key.public_key()
    validity = leaf.not_valid_after_utc - leaf.not_valid_before_utc
    assert validity == timedelta(days=BUILTIN_PROFILES["tls_server"].validity_days)
    assert {host for host, _, _ in checker.calls} == {"www.example.test", "api.example.test"}
    _, token, expected = checker.calls[0]
    assert expected.startswith(token + ".")
    request = await CertificateRequest.get(channel=Channel.ACME)
    assert request.requester == f"acme:{acme_client.kid.rsplit('/', 1)[1]}"  # type: ignore[union-attr]
    orders = await acme_client.get(f"{acme_client.kid}/orders")
    assert orders.json() == {"orders": [order_url]}


async def test_order_document(acme_client: AcmeClient) -> None:
    created = await acme_client.order("WWW.Example.TEST.", "www.example.test")
    document = created.json()
    authz = (await acme_client.get(document["authorizations"][0])).json()

    assert document["status"] == "pending"
    assert document["identifiers"] == [{"type": "dns", "value": "www.example.test"}]
    assert authz["identifier"] == {"type": "dns", "value": "www.example.test"}
    assert [c["type"] for c in authz["challenges"]] == ["dns-01", "http-01"]
    assert authz["challenges"][0]["status"] == "pending"


@pytest.mark.parametrize(
    ("identifiers", "code"),
    [
        ([{"type": "dns", "value": "*.*.example.test"}], "rejectedIdentifier"),
        ([{"type": "dns", "value": "nodot"}], "rejectedIdentifier"),
        ([{"type": "ip", "value": "not-an-ip"}], "malformed"),
        ([{"type": "email", "value": "a@b.test"}], "unsupportedIdentifier"),
        ([], "malformed"),
    ],
)
async def test_refused_identifiers(
    acme_client: AcmeClient, identifiers: list[dict[str, str]], code: str
) -> None:
    response = await acme_client.post(
        acme_client.directory["newOrder"], {"identifiers": identifiers}
    )

    assert problem(response) == code


async def test_custom_validity_refused(acme_client: AcmeClient) -> None:
    response = await acme_client.post(
        acme_client.directory["newOrder"],
        {
            "identifiers": [{"type": "dns", "value": "a.example.test"}],
            "notAfter": "2030-01-01T00:00:00Z",
        },
    )

    assert problem(response) == "malformed"


async def test_profile_without_dns_names(acme_client: AcmeClient) -> None:
    response = await acme_client.post(
        f"{BASE}/acme/ocsp_signer/new-order",
        {"identifiers": [{"type": "dns", "value": "a.example.test"}]},
    )

    assert problem(response) == "rejectedIdentifier"


async def test_failed_validation_after_three_attempts(
    acme_client: AcmeClient, app: FastAPI, checker: FakeChecker
) -> None:
    checker.failures = 3
    created = await acme_client.order("down.example.test")
    await validate_all(acme_client, app, created.json())

    order = (await acme_client.get(created.headers["Location"])).json()
    authz = (await acme_client.get(created.json()["authorizations"][0])).json()

    assert len(checker.calls) == 3
    assert order["status"] == "invalid" and authz["status"] == "invalid"
    [http] = [c for c in authz["challenges"] if c["type"] == "http-01"]
    assert http["error"]["type"] == PROBLEM + "connection"


async def test_validation_retried_then_valid(
    acme_client: AcmeClient, app: FastAPI, checker: FakeChecker
) -> None:
    checker.failures = 2
    created = await acme_client.order("flaky.example.test")
    await validate_all(acme_client, app, created.json())

    order = (await acme_client.get(created.headers["Location"])).json()

    assert len(checker.calls) == 3 and order["status"] == "ready"


async def test_validation_resumed_after_a_restart(
    acme_client: AcmeClient, checker: FakeChecker
) -> None:
    created = await acme_client.order("resume.example.test")
    authz = (await acme_client.get(created.json()["authorizations"][0])).json()
    challenge_id = http01(authz)["url"].rsplit("/", 1)[1]
    # As if the server stopped during an attempt: processing, lease expired.
    await AcmeChallenge.filter(id=challenge_id).update(
        status=ChallengeStatus.PROCESSING, attempts=1,
        next_attempt_at=datetime.now(UTC) - timedelta(seconds=1),
    )  # fmt: skip
    restarted = AcmeValidation(checker)

    started = await restarted.resume()
    await restarted.drain()

    assert started == 1 and len(checker.calls) == 1
    assert (await AcmeChallenge.get(id=challenge_id)).status is ChallengeStatus.VALID


async def test_finalize_before_ready(acme_client: AcmeClient) -> None:
    created = await acme_client.order("early.example.test")
    key = ec.generate_private_key(ec.SECP256R1())

    response = await acme_client.post(
        created.json()["finalize"], {"csr": b64url(csr_der(key, ["early.example.test"]))}
    )

    assert problem(response) == "orderNotReady" and response.status_code == 403


@pytest.mark.parametrize(
    "case", ["extra_san", "missing_san", "account_key", "common_name", "organization", "ip"]
)
async def test_bad_csr(acme_client: AcmeClient, app: FastAPI, case: str) -> None:
    created = await acme_client.order("a.example.test", "b.example.test")
    await validate_all(acme_client, app, created.json())
    key = ec.generate_private_key(ec.SECP256R1())
    names = ["a.example.test", "b.example.test"]
    if case == "extra_san":
        der = csr_der(key, [*names, "c.example.test"])
    elif case == "missing_san":
        der = csr_der(key, names[:1])
    elif case == "account_key":
        der = csr_der(acme_client.key, names)  # type: ignore[arg-type]
    elif case == "common_name":
        der = csr_der(key, names, common_name="c.example.test")
    elif case == "ip":
        der = csr_der(key, names, ips=["192.0.2.1"])
    else:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID

        der = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil")]))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False
            )
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )

    response = await acme_client.post(created.json()["finalize"], {"csr": b64url(der)})
    order = (await acme_client.get(created.headers["Location"])).json()

    assert problem(response) == "badCSR"
    assert order["status"] == "ready"  # the client may finalize again with a good CSR


async def test_common_name_among_the_identifiers(acme_client: AcmeClient, app: FastAPI) -> None:
    created = await acme_client.order("a.example.test")
    await validate_all(acme_client, app, created.json())
    key = ec.generate_private_key(ec.SECP256R1())

    response = await acme_client.post(
        created.json()["finalize"],
        {"csr": b64url(csr_der(key, ["a.example.test"], common_name="a.example.test"))},
    )

    assert response.json()["status"] == "valid"


async def test_orders_of_another_account(
    acme_client: AcmeClient, client: AsyncClient, app: FastAPI
) -> None:
    order_url, final, _ = await issue(acme_client, app, "mine.example.test")
    other = AcmeClient(client, ec.generate_private_key(ec.SECP256R1()))
    await other.register()

    for url in (order_url, final["certificate"], final["authorizations"][0]):
        response = await other.get(url)
        assert response.status_code == 404 and problem(response) == "unauthorized"


async def acme_issue_audit() -> AuditLog:
    [entry] = [
        e
        for e in await AuditLog.filter(action="certificate.issue")
        if e.details["channel"] == "acme"
    ]
    return entry


# --- lab mode and manual approval -------------------------------------------------------------


async def test_lab_mode(
    acme_client: AcmeClient, app: FastAPI, checker: FakeChecker, caplog: pytest.LogCaptureFixture
) -> None:
    await SettingsService().set("acme.insecure_skip_validation", True, actor="cli")

    with caplog.at_level(logging.WARNING):
        _, final, _ = await issue(acme_client, app, "lab.example.test")

    assert final["status"] == "valid" and checker.calls == []
    assert "lab mode" in caplog.text
    issued = await acme_issue_audit()
    finalized = await AuditLog.get(action="acme.order.finalize")
    assert issued.details["insecure_skip_validation"] is True
    assert finalized.details["insecure_skip_validation"] is True


async def test_no_lab_flag_normally(acme_client: AcmeClient, app: FastAPI) -> None:
    await issue(acme_client, app, "real.example.test")

    issued = await acme_issue_audit()
    assert "insecure_skip_validation" not in issued.details


@pytest.mark.parametrize("decision", ["approve", "reject"])
async def test_manual_approval(
    acme_client: AcmeClient, app: FastAPI, client: AsyncClient, decision: str
) -> None:
    await SettingsService().set("acme.manual_approval", True, actor="cli")
    order_url, final, _ = await issue(acme_client, app, "manual.example.test")
    pending = await acme_client.get(order_url)
    request = await CertificateRequest.get(channel=Channel.ACME)

    body = {"reason": "not today"} if decision == "reject" else None
    decided = await client.post(f"/api/v1/requests/{request.id}/{decision}", json=body)
    after = await acme_client.get(order_url)

    assert final["status"] == "processing" and pending.headers["Retry-After"] == "60"
    assert decided.status_code == 200, decided.text
    if decision == "approve":
        assert after.json()["status"] == "valid" and "certificate" in after.json()
        assert "Retry-After" not in after.headers
    else:
        assert after.json()["status"] == "invalid"
        assert "not today" in after.json()["error"]["detail"]


# --- secrets ----------------------------------------------------------------------------------


async def test_no_token_nor_nonce_in_logs_and_audit(
    acme_client: AcmeClient, app: FastAPI, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        _, final, _ = await issue(acme_client, app, "secret.example.test")
    tokens = await AcmeChallenge.all().values_list("token", flat=True)
    audit = " ".join(str(entry.details) for entry in await AuditLog.all())
    # The loggers of the server (logs.SERVER_LOGGERS); Tortoise stays at WARNING in the server.
    text = "\n".join(r.getMessage() for r in caplog.records if r.name.startswith(SERVER_LOGGERS))

    assert final["status"] == "valid" and "secret.example.test" in text
    for token in tokens:
        assert token not in text and token not in audit
    assert (acme_client.nonce or "x") not in text


# --- health, listener, task -------------------------------------------------------------------


async def test_health(client: AsyncClient, make_root: RootFactory) -> None:
    await make_root()
    disabled = (await client.get("/health")).json()
    await SettingsService().set("acme.enabled", True, actor="cli")
    await SettingsService().set("acme.insecure_skip_validation", True, actor="cli")
    lab = (await client.get("/health")).json()

    assert disabled["acme"] == "disabled"
    assert lab["acme"] == {"lab_mode": True, "manual_approval": False}
    assert any("ACME lab mode" in warning for warning in lab["warnings"])


def test_acme_is_https_only() -> None:
    from h42pki.api.listener import served_over_http

    assert not served_over_http("/acme/directory")
    assert not served_over_http("/acme/new-nonce")


async def test_acme_task_resumes_and_purges(acme_client: AcmeClient, app: FastAPI) -> None:
    from h42pki.tasks.maintenance import acme_task

    created = await acme_client.order("task.example.test")
    authz = (await acme_client.get(created.json()["authorizations"][0])).json()
    challenge_id = http01(authz)["url"].rsplit("/", 1)[1]
    await AcmeChallenge.filter(id=challenge_id).update(
        status=ChallengeStatus.PROCESSING, next_attempt_at=datetime.now(UTC)
    )
    await AcmeNonce.create(value="old", expires_at=datetime.now(UTC) - timedelta(seconds=1))

    await acme_task(app.state.acme_validation).run_once()
    await app.state.acme_validation.drain()

    assert (await AcmeChallenge.get(id=challenge_id)).status is ChallengeStatus.VALID
    assert not await AcmeNonce.filter(value="old").exists()


# --- dns-01 and wildcards ---------------------------------------------------------------------


async def test_wildcard_with_dns01(
    acme_client: AcmeClient, app: FastAPI, checker: FakeChecker
) -> None:
    import hashlib

    from h42pki.core.acme.jws import jwk_of, thumbprint

    _, final, _ = await issue(acme_client, app, "*.example.test", "example.test")
    wildcard, plain = [(await acme_client.get(url)).json() for url in final["authorizations"]]
    leaf = x509.load_pem_x509_certificates((await acme_client.get(final["certificate"])).content)[0]

    assert final["identifiers"] == [
        {"type": "dns", "value": "*.example.test"}, {"type": "dns", "value": "example.test"},
    ]  # fmt: skip
    assert wildcard["identifier"] == {"type": "dns", "value": "example.test"}
    assert wildcard["wildcard"] is True and [c["type"] for c in wildcard["challenges"]] == [
        "dns-01"
    ]
    assert "wildcard" not in plain and plain["status"] == "valid"
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sorted(sans.get_values_for_type(x509.DNSName)) == ["*.example.test", "example.test"]
    # dns-01: TXT _acme-challenge.example.test = base64url(SHA-256(key authorization)).
    token = wildcard["challenges"][0]["token"]
    key_auth = f"{token}.{thumbprint(jwk_of(acme_client.key.public_key()))}"
    assert checker.dns_calls == [
        ("example.test", b64url(hashlib.sha256(key_auth.encode()).digest()), [])
    ]


async def test_dns01_resolvers_and_failure(
    acme_client: AcmeClient, app: FastAPI, checker: FakeChecker
) -> None:
    await SettingsService().set("acme.dns_resolvers", ["10.89.0.53:8053"], actor="cli")
    checker.failures = 3
    created = await acme_client.order("*.down.example.test")
    await validate_all(acme_client, app, created.json(), kind="dns-01")

    order = (await acme_client.get(created.headers["Location"])).json()

    assert order["status"] == "invalid"
    assert [r for _, _, r in checker.dns_calls] == [["10.89.0.53:8053"]] * 3


# --- IP identifiers (RFC 8738) ----------------------------------------------------------------


async def test_ip_identifiers(acme_client: AcmeClient, app: FastAPI, checker: FakeChecker) -> None:
    created = await acme_client.order("192.0.2.10", "2001:DB8::10", kind="ip")
    authz = (await acme_client.get(created.json()["authorizations"][1])).json()
    _, final, _ = await issue(acme_client, app, ips=("192.0.2.10", "2001:db8::10"))
    leaf = x509.load_pem_x509_certificates((await acme_client.get(final["certificate"])).content)[0]

    assert created.json()["identifiers"][1] == {"type": "ip", "value": "2001:db8::10"}
    assert [c["type"] for c in authz["challenges"]] == ["http-01"]
    assert {host for host, _, _ in checker.calls} == {"192.0.2.10", "[2001:db8::10]"}
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sorted(str(ip) for ip in sans.get_values_for_type(x509.IPAddress)) == [
        "192.0.2.10", "2001:db8::10",
    ]  # fmt: skip


async def test_ip_refused_by_the_profile(acme_client: AcmeClient) -> None:
    response = await acme_client.post(
        f"{BASE}/acme/tls_client/new-order", {"identifiers": [{"type": "ip", "value": "192.0.2.1"}]}
    )

    assert problem(response) == "rejectedIdentifier"


# --- revokeCert -------------------------------------------------------------------------------


@pytest.fixture
async def revocable(client: AsyncClient, make_root: RootFactory, checker: FakeChecker) -> None:
    await make_root(crl=True, ocsp=True, public_base_url="http://ca.test")
    await SettingsService().set("acme.enabled", True, actor="cli")


async def registered(client: AsyncClient) -> AcmeClient:
    acme_client = AcmeClient(client, ec.generate_private_key(ec.SECP256R1()))
    assert (await acme_client.register()).status_code == 201
    return acme_client


async def ocsp_status(client: AsyncClient, leaf: x509.Certificate) -> Any:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import ocsp

    from h42pki.models import Authority
    from h42pki.models import Certificate as CertificateRecord

    authority = await Authority.get(kind="local")
    root = x509.load_der_x509_certificate(
        (await CertificateRecord.get(authority_id=authority.id)).der
    )
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(leaf, root, hashes.SHA1())  # noqa: S303 - CertID of RFC 5019
        .build()
        .public_bytes(serialization.Encoding.DER)
    )
    response = await client.post(
        "/ocsp", content=request, headers={"content-type": "application/ocsp-request"}
    )
    return ocsp.load_der_ocsp_response(response.content).certificate_status


@pytest.mark.usefixtures("revocable")
@pytest.mark.parametrize("signer", ["account", "certificate_key"])
async def test_revoke_cert(client: AsyncClient, app: FastAPI, signer: str) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509 import ocsp

    from h42pki.models import Certificate as CertificateRecord
    from h42pki.models import CertificateStatus, Crl

    acme_client = await registered(client)
    _, final, key = await issue(acme_client, app, "revoke.example.test")
    leaf = x509.load_pem_x509_certificates((await acme_client.get(final["certificate"])).content)[0]
    der = leaf.public_bytes(serialization.Encoding.DER)
    assert await ocsp_status(client, leaf) is ocsp.OCSPCertStatus.GOOD

    url = acme_client.directory["revokeCert"]
    payload = {"certificate": b64url(der), "reason": 4}
    if signer == "account":
        response = await acme_client.post(url, payload)
    else:
        response = await acme_client.post(url, payload, use_jwk=True, key=key)
    again = await acme_client.post(url, payload)

    assert response.status_code == 200 and response.content == b"", response.text
    assert problem(again) == "alreadyRevoked"
    record = await CertificateRecord.get(sha256_fingerprint=leaf.fingerprint(hashes_sha256()).hex())
    assert record.status is CertificateStatus.REVOKED
    assert record.revocation_reason is x509.ReasonFlags.superseded
    crl = x509.load_der_x509_crl((await Crl.all().order_by("-crl_number").first()).der)  # type: ignore[union-attr]
    assert crl.get_revoked_certificate_by_serial_number(leaf.serial_number) is not None
    assert await ocsp_status(client, leaf) is ocsp.OCSPCertStatus.REVOKED


def hashes_sha256() -> Any:
    from cryptography.hazmat.primitives import hashes

    return hashes.SHA256()


@pytest.mark.usefixtures("revocable")
async def test_revoke_cert_refused(client: AsyncClient, app: FastAPI) -> None:
    from cryptography.hazmat.primitives import serialization

    owner = await registered(client)
    other = await registered(client)
    _, final, _ = await issue(owner, app, "keep.example.test")
    leaf = x509.load_pem_x509_certificates((await owner.get(final["certificate"])).content)[0]
    der = b64url(leaf.public_bytes(serialization.Encoding.DER))
    url = owner.directory["revokeCert"]

    by_other = await other.post(url, {"certificate": der})
    by_other_key = await other.post(url, {"certificate": der}, use_jwk=True)
    suspension = await owner.post(url, {"certificate": der, "reason": 6})
    ca_compromise = await owner.post(url, {"certificate": der, "reason": 2})
    unknown = await owner.post(url, {"certificate": b64url(b"\x30\x00")})

    assert problem(by_other) == "unauthorized" and problem(by_other_key) == "unauthorized"
    assert problem(suspension) == "badRevocationReason"
    assert problem(ca_compromise) == "badRevocationReason"
    assert problem(unknown) == "malformed"


# --- administration ---------------------------------------------------------------------------


async def test_admin_accounts(acme_client: AcmeClient, client: AsyncClient, app: FastAPI) -> None:
    await issue(acme_client, app, "admin.example.test")
    account_id = (acme_client.kid or "").rsplit("/", 1)[1]

    listed = (await client.get("/api/v1/acme/accounts")).json()
    shown = (await client.get(f"/api/v1/acme/accounts/{account_id}")).json()
    deactivated = await client.post(f"/api/v1/acme/accounts/{account_id}/deactivate")
    after = await acme_client.get(acme_client.kid or "")
    missing = await client.get("/api/v1/acme/accounts/00000000-0000-0000-0000-000000000000")

    assert [a["id"] for a in listed] == [account_id]
    assert shown["orders"] == 1 and shown["key_type"] == "EC" and shown["status"] == "valid"
    assert deactivated.json()["status"] == "deactivated"
    assert problem(after) == "unauthorized"
    assert missing.status_code == 404
    entry = await AuditLog.filter(action="acme.account.deactivate").first()
    assert entry is not None and entry.actor == "anonymous"
