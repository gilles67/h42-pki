"""http-01 over the network (RFC 8555 section 8.3), against a local HTTP server."""

import asyncio
from collections.abc import AsyncIterator

import pytest

from h42pki.core.acme.errors import AcmeError
from h42pki.services.acme import validation
from h42pki.services.acme.validation import NetworkChecker

TOKEN = "tok"  # noqa: S105 - an ACME token
EXPECTED = "tok.thumbprint"
Routes = dict[str, tuple[int, dict[str, str], bytes]]


@pytest.fixture
async def server() -> AsyncIterator[tuple[int, Routes]]:
    """HTTP/1.0 server on 127.0.0.1: path → (status, headers, body)."""
    routes: Routes = {}

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = (await reader.readline()).decode()
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        path = line.split(" ")[1] if " " in line else "/"
        status, headers, body = routes.get(path, (404, {}, b"no"))
        head = f"HTTP/1.0 {status} X\r\nContent-Length: {len(body)}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        writer.write(head.encode() + b"\r\n" + body)
        await writer.drain()
        writer.close()

    listener = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    async with listener:
        yield port, routes


PATH = f"/.well-known/acme-challenge/{TOKEN}"


async def test_valid_answer_with_trailing_whitespace(server: tuple[int, Routes]) -> None:
    port, routes = server
    routes[PATH] = (200, {}, EXPECTED.encode() + b"\r\n")

    await NetworkChecker().http01(f"127.0.0.1:{port}", TOKEN, EXPECTED)


@pytest.mark.parametrize(
    ("answer", "code"),
    [
        ((200, {}, b"something else"), "incorrectResponse"),
        ((404, {}, b""), "unauthorized"),
        ((200, {}, b"x" * 9000), "incorrectResponse"),
        ((302, {"Location": "http://127.0.0.1:8081/elsewhere"}, b""), "connection"),
        ((302, {"Location": "ftp://127.0.0.1/x"}, b""), "connection"),
    ],
)
async def test_refused_answers(
    server: tuple[int, Routes], answer: tuple[int, dict[str, str], bytes], code: str
) -> None:
    port, routes = server
    routes[PATH] = answer

    with pytest.raises(AcmeError) as raised:
        await NetworkChecker().http01(f"127.0.0.1:{port}", TOKEN, EXPECTED)

    assert raised.value.code == code
    assert EXPECTED not in raised.value.detail and TOKEN not in raised.value.detail


async def test_redirection_loop(
    server: tuple[int, Routes], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, routes = server
    monkeypatch.setattr(validation, "REDIRECT_PORTS", (80, 443, port))  # the test port
    routes[PATH] = (302, {"Location": PATH}, b"")

    with pytest.raises(AcmeError, match="more than 10 redirections"):
        await NetworkChecker().http01(f"127.0.0.1:{port}", TOKEN, EXPECTED)


async def test_redirection_followed(
    server: tuple[int, Routes], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, routes = server
    monkeypatch.setattr(validation, "REDIRECT_PORTS", (80, 443, port))
    routes[PATH] = (301, {"Location": "/moved"}, b"")
    routes["/moved"] = (200, {}, EXPECTED.encode())

    await NetworkChecker().http01(f"127.0.0.1:{port}", TOKEN, EXPECTED)


async def test_unreachable() -> None:
    with pytest.raises(AcmeError) as raised:
        await NetworkChecker().http01("127.0.0.1:1", TOKEN, EXPECTED)

    assert raised.value.code == "connection"
