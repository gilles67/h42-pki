"""ACME JWS, JWK and thumbprints (RFC 7515, RFC 7638, RFC 8037, RFC 8555 section 6.2)."""

import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from h42pki.core.acme import jws as acme_jws
from h42pki.core.acme.errors import AcmeError
from h42pki.core.acme.jws import b64url
from tests.acme_jws import PrivateKey, jws

URL = "https://ca.test/acme/new-account"

# RFC 7638 section 3.1.
RFC7638_JWK = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP"
        "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY"
        "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f"
        "M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
# RFC 8037 appendix A.2 and A.3.
RFC8037_JWK = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
RFC8037_THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


@pytest.fixture(scope="module")
def keys() -> dict[str, PrivateKey]:
    return {
        "RS256": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "ES256": ec.generate_private_key(ec.SECP256R1()),
        "ES384": ec.generate_private_key(ec.SECP384R1()),
        "EdDSA": ed25519.Ed25519PrivateKey.generate(),
    }


def flattened(protected: dict[str, Any], payload: bytes = b"", signature: bytes = b"x") -> bytes:
    return json.dumps(
        {
            "protected": b64url(json.dumps(protected).encode()),
            "payload": b64url(payload),
            "signature": b64url(signature),
        }
    ).encode()


def code_of(body: bytes) -> str:
    with pytest.raises(AcmeError) as raised:
        acme_jws.parse(body)
    return raised.value.code


def test_rfc7638_thumbprints() -> None:
    assert acme_jws.thumbprint(RFC7638_JWK) == RFC7638_THUMBPRINT
    assert acme_jws.thumbprint(RFC8037_JWK) == RFC8037_THUMBPRINT


def test_rfc8037_ed25519_signature() -> None:
    parsed = acme_jws.Jws(
        protected={"alg": "EdDSA"},
        signing_input=b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc",
        payload=b"Example of Ed25519 signing",
        signature=acme_jws.b64url_decode(
            "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
        ),
    )

    acme_jws.verify(parsed, acme_jws.public_key(RFC8037_JWK))


def test_rfc7515_es256_signature() -> None:
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    }
    parsed = acme_jws.Jws(
        protected={"alg": "ES256"},
        signing_input=(
            b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
            b"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        ),
        payload=b"",
        signature=acme_jws.b64url_decode(
            "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        ),
    )

    acme_jws.verify(parsed, acme_jws.public_key(jwk))


@pytest.mark.parametrize("alg", ["RS256", "ES256", "ES384", "EdDSA"])
def test_round_trip(keys: dict[str, PrivateKey], alg: str) -> None:
    key = keys[alg]
    body = jws(key, {"termsOfServiceAgreed": True}, url=URL, nonce="n1")

    parsed = acme_jws.parse(body)
    acme_jws.verify(parsed, acme_jws.public_key(parsed.jwk or {}))

    assert (parsed.alg, parsed.url, parsed.nonce) == (alg, URL, "n1")
    assert parsed.json_payload() == {"termsOfServiceAgreed": True}
    assert acme_jws.public_key_der(
        acme_jws.public_key(parsed.jwk or {})
    ) == acme_jws.public_key_der(key.public_key())


def test_post_as_get_payload(keys: dict[str, PrivateKey]) -> None:
    parsed = acme_jws.parse(jws(keys["ES256"], None, url=URL, nonce="n", kid="https://ca/acct/1"))

    assert (
        parsed.json_payload() is None and parsed.kid == "https://ca/acct/1" and parsed.jwk is None
    )


@pytest.mark.parametrize("alg", ["none", "HS256", "RS512", None])
def test_forbidden_algorithms(alg: str | None) -> None:
    body = flattened({"alg": alg, "jwk": {}, "url": URL, "nonce": "n"})

    assert code_of(body) == "badSignatureAlgorithm"


@pytest.mark.parametrize(
    ("header", "code"),
    [
        ({"alg": "ES256", "url": URL, "nonce": "n"}, "malformed"),  # neither jwk nor kid
        ({"alg": "ES256", "jwk": {}, "kid": "k", "url": URL, "nonce": "n"}, "malformed"),
        ({"alg": "ES256", "kid": "k", "nonce": "n"}, "malformed"),  # no url
        ({"alg": "ES256", "kid": "k", "url": URL}, "badNonce"),  # no nonce
        ({"alg": "ES256", "kid": 3, "url": URL, "nonce": "n"}, "malformed"),
        ({"alg": "ES256", "kid": "k", "url": URL, "nonce": "n", "crit": ["x"]}, "malformed"),
    ],
)
def test_header_rules(header: dict[str, Any], code: str) -> None:
    assert code_of(flattened(header)) == code


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b'{"protected": "e30", "payload": ""}',
        b'{"protected": "e30", "payload": "", "signature": "", "header": {}}',
        b'{"protected": "e30=", "payload": "", "signature": ""}',  # padding
        b'{"protected": "e+0", "payload": "", "signature": ""}',  # not url-safe
        b'{"protected": "e31", "payload": "", "signature": ""}',  # non-canonical bits
        b'{"protected": "W10", "payload": "", "signature": ""}',  # header is a list
    ],
)
def test_malformed_requests(body: bytes) -> None:
    assert code_of(body) == "malformed"


def test_wrong_signature(keys: dict[str, PrivateKey]) -> None:
    parsed = acme_jws.parse(jws(keys["RS256"], {}, url=URL, nonce="n"))
    other = acme_jws.parse(jws(keys["ES256"], {}, url=URL, nonce="n"))

    with pytest.raises(AcmeError) as bad:
        acme_jws.verify(parsed, rsa.generate_private_key(65537, 2048).public_key())
    with pytest.raises(AcmeError) as mismatch:
        acme_jws.verify(other, keys["RS256"].public_key())  # type: ignore[arg-type]

    assert bad.value.code == "malformed"
    assert mismatch.value.code == "badSignatureAlgorithm"


@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "oct", "k": "AAAA"},
        {"kty": "EC", "crv": "P-521", "x": "AA", "y": "AA"},
        {"kty": "OKP", "crv": "X25519", "x": RFC8037_JWK["x"]},
        {"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"},
        {**RFC8037_JWK, "d": "AAAA"},
    ],
)
def test_bad_public_keys(jwk: dict[str, Any]) -> None:
    with pytest.raises(AcmeError) as raised:
        acme_jws.public_key(jwk)

    assert raised.value.code == "badPublicKey"


def test_small_rsa_key_refused() -> None:
    small = rsa.generate_private_key(65537, 1024).public_key()  # noqa: S505 - refused on purpose

    with pytest.raises(AcmeError) as raised:
        acme_jws.public_key(acme_jws.jwk_of(small))

    assert raised.value.code == "badPublicKey"


def test_key_authorization() -> None:
    assert acme_jws.key_authorization("tok", RFC7638_JWK) == f"tok.{RFC7638_THUMBPRINT}"


def test_problem_document() -> None:
    problem = AcmeError("badSignatureAlgorithm", "no").document()

    assert problem["type"] == "urn:ietf:params:acme:error:badSignatureAlgorithm"
    assert problem["status"] == 400 and problem["algorithms"] == [
        "RS256",
        "ES256",
        "ES384",
        "EdDSA",
    ]
    assert AcmeError("orderNotReady", "x").http_status == 403
    with pytest.raises(ValueError, match="unknown ACME error"):
        AcmeError("nope", "x")
