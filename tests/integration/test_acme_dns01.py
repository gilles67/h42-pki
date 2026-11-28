"""dns-01 over the network (RFC 8555 section 8.4), against a local DNS server on UDP."""

import asyncio
from collections.abc import AsyncIterator

import dns.message
import dns.rcode
import dns.rrset
import pytest

from h42pki.core.acme.errors import AcmeError
from h42pki.services.acme.validation import NetworkChecker

Records = dict[str, list[str]]


class _Server(asyncio.DatagramProtocol):
    def __init__(self, records: Records) -> None:
        self.records = records

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        name = query.question[0].name.to_text()
        values = self.records.get(name)
        if values is None:
            response.set_rcode(dns.rcode.NXDOMAIN)
        elif values:
            response.answer.append(
                dns.rrset.from_text_list(name, 60, "IN", "TXT", [f'"{v}"' for v in values])
            )
        self.transport.sendto(response.to_wire(), addr)  # type: ignore[attr-defined]


@pytest.fixture
async def server() -> AsyncIterator[tuple[str, Records]]:
    records: Records = {}
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _Server(records), local_addr=("127.0.0.1", 0)
    )
    port = transport.get_extra_info("sockname")[1]
    yield f"127.0.0.1:{port}", records
    transport.close()


NAME = "_acme-challenge.example.test."


async def test_txt_found_among_others(server: tuple[str, Records]) -> None:
    resolver, records = server
    records[NAME] = ["other-value", "expected-digest"]  # a wildcard and its base share the name

    await NetworkChecker().dns01("example.test", "expected-digest", [resolver])


@pytest.mark.parametrize(
    ("values", "code"),
    [(None, "dns"), ([], "dns"), (["wrong"], "incorrectResponse")],
)
async def test_refused(server: tuple[str, Records], values: list[str] | None, code: str) -> None:
    resolver, records = server
    if values is not None:
        records[NAME] = values

    with pytest.raises(AcmeError) as raised:
        await NetworkChecker().dns01("example.test", "expected-digest", [resolver])

    assert raised.value.code == code and "expected-digest" not in raised.value.detail
