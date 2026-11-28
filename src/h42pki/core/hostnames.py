"""Names of the service: FQDN, extra DNS names / IP addresses, trusted proxy networks (ADR-0011).

``H42_PKI_SERVER_HOSTNAME`` must be a real fully qualified domain name: it becomes the common
name and first SAN of the built-in HTTPS certificate (ADR-0013). ``H42_PKI_SERVER_ALT_NAMES``
adds DNS names (short names such as a ``docker compose`` service are allowed) and IP addresses.
"""

import ipaddress
import re
from collections.abc import Iterable

from h42pki.core.errors import InvalidHostname, InvalidNetwork

MAX_NAME_LENGTH = 253
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

type IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _normalize_dns(value: str, *, min_labels: int, what: str) -> str:
    name = value.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    if not name:
        raise InvalidHostname(f"{what} is empty")
    if "*" in name:
        raise InvalidHostname(f"{what} {name!r}: wildcards are not allowed")
    if len(name) > MAX_NAME_LENGTH:
        raise InvalidHostname(f"{what} is longer than {MAX_NAME_LENGTH} characters")
    labels = name.split(".")
    if len(labels) < min_labels:
        raise InvalidHostname(
            f"{what} {name!r} is not a fully qualified domain name (at least two labels)"
        )
    for label in labels:
        if not _LABEL.match(label):
            raise InvalidHostname(
                f"{what} {name!r}: each label must have 1 to 63 characters a-z, 0-9 or '-', "
                "and must not start or end with '-'"
            )
    if labels[-1].isdigit():
        raise InvalidHostname(f"{what} {name!r}: the last label must not be numeric")
    return name


def normalize_dns_name(value: str, *, what: str = "DNS name") -> str:
    """A fully qualified DNS name (at least two labels), lower case, without wildcard nor IP."""
    if _is_ip(value.strip()):
        raise InvalidHostname(f"{what} {value.strip()!r} is an IP address")
    return _normalize_dns(value, min_labels=2, what=what)


def normalize_fqdn(value: str) -> str:
    """Validate the service FQDN: lower case, trailing dot removed; never an IP or a wildcard."""
    if _is_ip(value.strip()):
        raise InvalidHostname(f"server hostname {value.strip()!r} is an IP address, not a FQDN")
    return _normalize_dns(value, min_labels=2, what="server hostname")


def normalize_alt_name(value: str) -> str:
    """One extra name: an IP address (normalized) or a DNS name (short names allowed)."""
    stripped = value.strip()
    try:
        return str(ipaddress.ip_address(stripped))
    except ValueError:
        return _normalize_dns(stripped, min_labels=1, what="alternative name")


def normalize_alt_names(values: Iterable[str], *, primary: str | None = None) -> list[str]:
    """Normalize extra names, dropping empty items, duplicates and the primary hostname."""
    names: list[str] = []
    for value in values:
        if not value.strip():
            continue
        name = normalize_alt_name(value)
        if name != primary and name not in names:
            names.append(name)
    return names


def is_ip_address(name: str) -> bool:
    """True if a normalized alternative name is an IP address (SAN of type ip)."""
    return _is_ip(name)


def parse_network(value: str) -> IPNetwork:
    """A CIDR (``10.0.0.0/8``, ``fd00::/8``) or a single address; host bits are cleared."""
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise InvalidNetwork(f"{value.strip()!r} is not a valid network (CIDR)") from None


def parse_networks(values: Iterable[str]) -> list[IPNetwork]:
    networks: list[IPNetwork] = []
    for value in values:
        if value.strip():
            network = parse_network(value)
            if network not in networks:
                networks.append(network)
    return networks


def split_list(value: str) -> list[str]:
    """Split a comma-separated environment variable."""
    return [item.strip() for item in value.split(",") if item.strip()]
