"""core.crl: full CRL of a CA, revocation reasons."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import CRLEntryExtensionOID, ExtensionOID

from h42pki.core.crl import (
    REVOCATION_REASONS,
    RevokedEntry,
    build_crl,
    check_invalidity_date,
    crl_due,
    revocation_reason,
)
from h42pki.core.errors import InvalidRevocation
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.core.serial import new_serial_hex
from tests.unit.core.test_issued import NOW, _root

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]
LATER = NOW + timedelta(days=365)


def entry(
    *,
    reason: x509.ReasonFlags | None = x509.ReasonFlags.key_compromise,
    invalidity_date: datetime | None = None,
    not_after: datetime = LATER,
    revoked_at: datetime = NOW - timedelta(hours=1),
) -> RevokedEntry:
    return RevokedEntry(new_serial_hex(), revoked_at, reason, invalidity_date, not_after)


def crl_of(
    key_for: KeyFor,
    entries: list[RevokedEntry],
    *,
    algorithm: KeyAlgorithm = KeyAlgorithm.EC_P384,
    number: int = 1,
) -> tuple[x509.CertificateRevocationList, x509.Certificate]:
    key = key_for(algorithm)
    issuer = _root(key)
    crl = build_crl(issuer, key, entries, crl_number=number, now=NOW, validity_hours=168)
    return crl, issuer


def test_empty_crl(key_for: KeyFor) -> None:
    crl, issuer = crl_of(key_for, [])

    assert len(crl) == 0
    assert crl.issuer == issuer.subject
    assert crl.last_update_utc == NOW
    assert crl.next_update_utc == NOW + timedelta(hours=168)
    number = crl.extensions.get_extension_for_class(x509.CRLNumber)
    assert not number.critical and number.value.crl_number == 1
    aki = crl.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert isinstance(aki.value, x509.AuthorityKeyIdentifier)
    assert not aki.critical and aki.value.key_identifier == ski.digest


@pytest.mark.parametrize(
    ("algorithm", "hash_type"),
    [
        (KeyAlgorithm.RSA2048, hashes.SHA256),
        (KeyAlgorithm.EC_P256, hashes.SHA256),
        (KeyAlgorithm.EC_P384, hashes.SHA384),
        (KeyAlgorithm.ED25519, type(None)),
    ],
)
def test_signature_follows_the_key(
    key_for: KeyFor, algorithm: KeyAlgorithm, hash_type: type
) -> None:
    crl, issuer = crl_of(key_for, [entry()], algorithm=algorithm)

    assert crl.is_signature_valid(issuer.public_key())
    assert isinstance(crl.signature_hash_algorithm, hash_type)


def test_reasons_and_invalidity_date(key_for: KeyFor) -> None:
    compromised = entry(invalidity_date=NOW - timedelta(days=2) + timedelta(microseconds=5))
    superseded = entry(reason=x509.ReasonFlags.superseded)

    crl, _ = crl_of(key_for, [compromised, superseded])

    first = crl.get_revoked_certificate_by_serial_number(int(compromised.serial_hex, 16))
    assert first is not None
    assert first.revocation_date_utc == compromised.revoked_at.replace(microsecond=0)
    reason = first.extensions.get_extension_for_class(x509.CRLReason)
    assert not reason.critical and reason.value.reason is x509.ReasonFlags.key_compromise
    invalidity = first.extensions.get_extension_for_class(x509.InvalidityDate).value
    assert invalidity.invalidity_date_utc == NOW - timedelta(days=2)
    second = crl.get_revoked_certificate_by_serial_number(int(superseded.serial_hex, 16))
    assert second is not None
    assert second.extensions.get_extension_for_class(x509.CRLReason).value.reason is (
        x509.ReasonFlags.superseded
    )
    oids = {extension.oid for extension in second.extensions}
    assert CRLEntryExtensionOID.INVALIDITY_DATE not in oids


@pytest.mark.parametrize("reason", [x509.ReasonFlags.unspecified, None])
def test_unspecified_reason_is_omitted(key_for: KeyFor, reason: x509.ReasonFlags | None) -> None:
    crl, _ = crl_of(key_for, [entry(reason=reason)])

    assert len(crl) == 1
    assert {extension.oid for extension in next(iter(crl)).extensions} == set()


def test_crl_number_is_written(key_for: KeyFor) -> None:
    numbers = [
        crl_of(key_for, [], number=number)[0]
        .extensions.get_extension_for_class(x509.CRLNumber)
        .value.crl_number
        for number in (1, 2, 41)
    ]

    assert numbers == [1, 2, 41]


def test_expired_revoked_certificate_is_left_out(key_for: KeyFor) -> None:
    expired = entry(not_after=NOW - timedelta(seconds=1))
    current = entry()

    crl, _ = crl_of(key_for, [expired, current])

    assert [revoked.serial_number for revoked in crl] == [int(current.serial_hex, 16)]


def test_entries_are_ordered_by_revocation_date(key_for: KeyFor) -> None:
    late = entry(revoked_at=NOW - timedelta(minutes=1))
    early = entry(revoked_at=NOW - timedelta(days=1))

    crl, _ = crl_of(key_for, [late, early])

    assert [revoked.serial_number for revoked in crl] == [
        int(early.serial_hex, 16),
        int(late.serial_hex, 16),
    ]


def test_naive_now_and_bad_number_refused(key_for: KeyFor) -> None:
    key = key_for(KeyAlgorithm.EC_P256)
    issuer = _root(key)

    with pytest.raises(ValueError, match="timezone"):
        build_crl(issuer, key, [], crl_number=1, now=datetime(2026, 1, 1), validity_hours=1)  # noqa: DTZ001
    with pytest.raises(ValueError, match="positive"):
        build_crl(issuer, key, [], crl_number=0, now=NOW, validity_hours=1)


# --- reasons and dates ------------------------------------------------------------------------


def test_every_reason_but_suspension_is_accepted() -> None:
    assert {reason.name for reason in REVOCATION_REASONS} == {
        "unspecified",
        "key_compromise",
        "ca_compromise",
        "affiliation_changed",
        "superseded",
        "cessation_of_operation",
        "privilege_withdrawn",
        "aa_compromise",
    }
    assert revocation_reason("key_compromise") is x509.ReasonFlags.key_compromise


@pytest.mark.parametrize("name", ["certificate_hold", "remove_from_crl"])
def test_suspension_is_refused(name: str) -> None:
    with pytest.raises(InvalidRevocation, match="suspension"):
        revocation_reason(name)


def test_unknown_reason_is_refused() -> None:
    with pytest.raises(InvalidRevocation, match="unknown revocation reason"):
        revocation_reason("keyCompromise")


def test_invalidity_date_checks() -> None:
    check_invalidity_date(None, NOW)
    check_invalidity_date(NOW, NOW)
    with pytest.raises(InvalidRevocation, match="future"):
        check_invalidity_date(NOW + timedelta(seconds=1), NOW)
    with pytest.raises(InvalidRevocation, match="time zone"):
        check_invalidity_date(datetime(2026, 1, 1), NOW)  # noqa: DTZ001


def test_crl_due() -> None:
    next_update = NOW + timedelta(hours=100)

    assert crl_due(None, NOW, regenerate_before_hours=48)
    assert not crl_due(next_update, NOW, regenerate_before_hours=48)
    assert crl_due(next_update, NOW + timedelta(hours=52), regenerate_before_hours=48)
    assert crl_due(next_update, datetime(2030, 1, 1, tzinfo=UTC), regenerate_before_hours=48)
