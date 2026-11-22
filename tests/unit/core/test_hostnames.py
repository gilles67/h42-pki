import ipaddress

import pytest

from h42pki.core.errors import InvalidHostname, InvalidNetwork
from h42pki.core.hostnames import (
    is_ip_address,
    normalize_alt_name,
    normalize_alt_names,
    normalize_fqdn,
    parse_network,
    parse_networks,
    split_list,
)

# --- FQDN (H42_PKI_SERVER_HOSTNAME) -------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("pki.home42.test", "pki.home42.test"),
        ("PKI.Home42.Test", "pki.home42.test"),  # lower case
        ("pki.home42.test.", "pki.home42.test"),  # trailing dot removed
        ("  pki.home42.test  ", "pki.home42.test"),
        ("a.b", "a.b"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),  # punycode
        ("pki-1.home-42.test", "pki-1.home-42.test"),
        ("1pki.home42.test", "1pki.home42.test"),  # numeric first labels are fine
        (f"{'a' * 63}.test", f"{'a' * 63}.test"),
    ],
)
def test_valid_fqdn(value: str, expected: str) -> None:
    assert normalize_fqdn(value) == expected


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("pki", "at least two labels"),
        ("", "empty"),
        (".", "empty"),
        ("*.home42.test", "wildcards"),
        ("192.168.1.10", "IP address"),
        ("::1", "IP address"),
        ("pki..test", "1 to 63"),  # empty label
        ("-pki.test", "must not start or end"),
        ("pki-.test", "must not start or end"),
        ("pki_1.test", "a-z, 0-9"),
        ("pki.héhé.test", "a-z, 0-9"),
        (f"{'a' * 64}.test", "1 to 63"),
        ("pki.home42.123", "last label must not be numeric"),
        (".".join(["a" * 63] * 4) + ".test", "longer than 253"),
    ],
)
def test_invalid_fqdn(value: str, reason: str) -> None:
    with pytest.raises(InvalidHostname, match=reason):
        normalize_fqdn(value)


# --- alternative names (H42_PKI_SERVER_ALT_NAMES) -------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("localhost", "localhost"),  # short names allowed
        ("pki-int", "pki-int"),
        ("PKI.Home42.test.", "pki.home42.test"),
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        ("2001:DB8:0:0::1", "2001:db8::1"),  # normalized IPv6
    ],
)
def test_valid_alt_name(value: str, expected: str) -> None:
    assert normalize_alt_name(value) == expected


@pytest.mark.parametrize("value", ["*.home42.test", "*", "pki_int", "-pki", "123", "256.1.1.1"])
def test_invalid_alt_name(value: str) -> None:
    with pytest.raises(InvalidHostname):
        normalize_alt_name(value)


def test_alt_names_drop_duplicates_empty_items_and_primary() -> None:
    names = normalize_alt_names(
        ["localhost", "", "LOCALHOST", "127.0.0.1", "pki.home42.test", "127.0.0.1"],
        primary="pki.home42.test",
    )

    assert names == ["localhost", "127.0.0.1"]


def test_is_ip_address() -> None:
    assert is_ip_address("127.0.0.1")
    assert is_ip_address("::1")
    assert not is_ip_address("localhost")


# --- trusted proxies ---------------------------------------------------------------------


def test_networks() -> None:
    assert parse_networks(["10.0.0.0/8", "fd00::/8", "", "10.0.0.0/8", "192.0.2.7"]) == [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("fd00::/8"),
        ipaddress.ip_network("192.0.2.7/32"),
    ]


def test_network_host_bits_are_cleared() -> None:
    assert parse_network("10.1.2.3/8") == ipaddress.ip_network("10.0.0.0/8")


@pytest.mark.parametrize("value", ["10.0.0.0/33", "proxy.local", "10.0.0/8x", "fd00::/129"])
def test_invalid_network(value: str) -> None:
    with pytest.raises(InvalidNetwork):
        parse_network(value)


def test_split_list() -> None:
    assert split_list(" a, b ,,c ") == ["a", "b", "c"]
    assert split_list("") == []
