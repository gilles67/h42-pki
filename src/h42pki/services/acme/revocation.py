"""revokeCert (RFC 8555 section 7.6), through ``RevocationService`` (CRL and OCSP cache).

Signed with the ``kid`` of the account whose order obtained the certificate, or with a ``jwk``
that is the key of the certificate. Reasons of RFC 5280 for an end-entity certificate; no
suspension (ADR-0017).
"""

import hashlib

from cryptography import x509

from h42pki.core.acme.errors import AcmeError
from h42pki.core.acme.jws import b64url_decode, public_key, public_key_der, thumbprint
from h42pki.errors import Conflict, ServiceUnavailable
from h42pki.keystore import KeyStore
from h42pki.models import AcmeOrder, Certificate, CertificateStatus
from h42pki.services.acme.accounts import actor_of
from h42pki.services.acme.auth import AcmeRequest
from h42pki.services.acme.payloads import RevokeCert, payload
from h42pki.services.revocation import RevocationListener, RevocationService

# RFC 5280 CRLReason codes accepted: cACompromise (2) and aACompromise (10) are not reasons for
# an end-entity certificate, certificateHold (6) and removeFromCRL (8) are suspensions, 7 unused.
REASONS = {
    0: x509.ReasonFlags.unspecified,
    1: x509.ReasonFlags.key_compromise,
    3: x509.ReasonFlags.affiliation_changed,
    4: x509.ReasonFlags.superseded,
    5: x509.ReasonFlags.cessation_of_operation,
    9: x509.ReasonFlags.privilege_withdrawn,
}


class AcmeRevocation:
    def __init__(
        self, keystore: KeyStore | None, on_revoked: RevocationListener | None = None
    ) -> None:
        self._keystore = keystore
        self._on_revoked = on_revoked

    async def revoke(self, request: AcmeRequest) -> Certificate:
        body = payload(RevokeCert, request.payload)
        der = b64url_decode(body.certificate, "certificate")
        try:
            certificate = x509.load_der_x509_certificate(der)
        except ValueError:
            raise AcmeError("malformed", "the certificate is not DER") from None
        reason = REASONS.get(body.reason if body.reason is not None else 0)
        if reason is None:
            raise AcmeError(
                "badRevocationReason",
                "accepted reasons: 0, 1, 3, 4, 5, 9 (no suspension, no CA compromise)",
            )
        record = await Certificate.get_or_none(sha256_fingerprint=hashlib.sha256(der).hexdigest())
        if record is None:
            raise AcmeError("malformed", "this certificate was not issued by this CA", status=404)
        if request.account is not None:
            owner = await AcmeOrder.filter(
                account_id=request.account.id, certificate_id=record.id
            ).exists()
            if not owner:
                raise AcmeError("unauthorized", "this account did not obtain this certificate")
            actor = actor_of(request.account)
        else:
            key = public_key_der(public_key(request.jwk))
            if key != public_key_der(certificate.public_key()):  # type: ignore[arg-type]
                raise AcmeError("unauthorized", "the jwk is not the key of the certificate")
            actor = f"acme-key:{thumbprint(request.jwk)}"
        if record.status is CertificateStatus.REVOKED:
            raise AcmeError("alreadyRevoked", "the certificate is already revoked")
        try:
            return await RevocationService(self._keystore, on_revoked=self._on_revoked).revoke(
                record.id, reason=reason, actor=actor
            )
        except Conflict as exc:
            if "already revoked" in exc.detail:
                raise AcmeError("alreadyRevoked", exc.detail) from None
            raise AcmeError("unauthorized", exc.detail) from None
        except ServiceUnavailable as exc:
            raise AcmeError("serverInternal", exc.detail, status=503) from None
