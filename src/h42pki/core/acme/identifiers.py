"""ACME identifiers (RFC 8555 section 7.1.4, RFC 8738) and the CSR of finalize (section 7.4).

``dns`` names are lower case, without trailing dot; ``*.name`` is a wildcard (dns-01 only, the
authorization is on ``name``). ``ip`` values are IPv4 or IPv6 addresses in canonical form.
"""

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID

from h42pki.core.acme.errors import AcmeError
from h42pki.core.csr import ParsedCsr
from h42pki.core.errors import InvalidHostname
from h42pki.core.hostnames import normalize_dns_name

MAX_IDENTIFIERS = 100
WILDCARD = "*."


@dataclass(frozen=True, order=True)
class Identifier:
    type: str  # "dns" | "ip"
    value: str  # as in the certificate: "*.example.test" for a wildcard

    @property
    def wildcard(self) -> bool:
        return self.type == "dns" and self.value.startswith(WILDCARD)

    @property
    def authorized_value(self) -> str:
        """What the authorization covers: the name without ``*.``."""
        return self.value[len(WILDCARD) :] if self.wildcard else self.value

    def document(self) -> dict[str, str]:
        return {"type": self.type, "value": self.value}


def _dns(value: str, *, allow_wildcard: bool) -> Identifier:
    name = value.strip().lower()
    wildcard = name.startswith(WILDCARD)
    if wildcard and not allow_wildcard:
        raise AcmeError("rejectedIdentifier", f"wildcard names are not accepted here: {value!r}")
    base = name[len(WILDCARD) :] if wildcard else name
    try:
        base = normalize_dns_name(base, what="identifier")
    except InvalidHostname as exc:
        raise AcmeError("rejectedIdentifier", exc.detail) from None
    return Identifier("dns", WILDCARD + base if wildcard else base)


def _ip(value: str) -> Identifier:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise AcmeError("malformed", f"{value!r} is not an IP address") from None
    return Identifier("ip", str(address))


def parse_identifiers(raw: Any, *, allow_wildcard: bool, allow_ip: bool) -> list[Identifier]:
    """The identifiers of a newOrder, normalized, without duplicates, in their order."""
    if not isinstance(raw, list) or not raw:
        raise AcmeError("malformed", "identifiers must be a non-empty list")
    if len(raw) > MAX_IDENTIFIERS:
        raise AcmeError("rejectedIdentifier", f"at most {MAX_IDENTIFIERS} identifiers per order")
    result: list[Identifier] = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("value"), str):
            raise AcmeError("malformed", "each identifier needs a type and a string value")
        kind = item.get("type")
        if kind == "dns":
            identifier = _dns(item["value"], allow_wildcard=allow_wildcard)
        elif kind == "ip" and allow_ip:
            identifier = _ip(item["value"])
        else:
            raise AcmeError("unsupportedIdentifier", f"identifier type {kind!r} is not supported")
        if identifier not in result:
            result.append(identifier)
    return result


def identifiers_of(documents: Iterable[dict[str, str]]) -> list[Identifier]:
    return [Identifier(d["type"], d["value"]) for d in documents]


def check_csr(parsed: ParsedCsr, identifiers: Iterable[Identifier]) -> None:
    """``badCSR`` unless the SANs (and a common name, if any) are exactly the identifiers.

    The subject may hold a common name only: anything else would not have been validated.
    """
    wanted = set(identifiers)
    found: set[Identifier] = set()
    for san in parsed.sans:
        if san.type == "dns":
            found.add(Identifier("dns", san.value.lower().rstrip(".")))
        elif san.type == "ip":
            found.add(Identifier("ip", str(ipaddress.ip_address(san.value))))
        else:
            raise AcmeError(
                "badCSR", f"the CSR asks for a {san.type} SAN, which ACME cannot validate"
            )
    if found != wanted:
        missing = sorted(i.value for i in wanted - found)
        extra = sorted(i.value for i in found - wanted)
        raise AcmeError(
            "badCSR",
            "the SANs of the CSR must be the identifiers of the order"
            + (f"; missing: {', '.join(missing)}" if missing else "")
            + (f"; not in the order: {', '.join(extra)}" if extra else ""),
        )
    subject: x509.Name = parsed.csr.subject
    for attribute in subject:
        if attribute.oid != NameOID.COMMON_NAME:
            raise AcmeError("badCSR", "the subject of the CSR may only hold a common name")
        value = str(attribute.value).lower().rstrip(".")
        if not any(i.value == value for i in wanted):
            raise AcmeError(
                "badCSR", "the common name of the CSR is not an identifier of the order"
            )
