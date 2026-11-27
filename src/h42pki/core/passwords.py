"""Passwords chosen by humans (EST accounts, ADR-0018): slow hash with scrypt, constant time.

Parameters: N = 2^15, r = 8, p = 3. OWASP lists them as equivalent to N = 2^17, r = 8, p = 1 (same
work) with 32 MiB of memory per hash instead of 128 MiB: about 0.15 s on the development machine,
reasonable for a homelab container that may check a few passwords at once. They are written in
each hash, so that they can be raised later without invalidating the existing ones.

Format: ``scrypt$<N>$<r>$<p>$<salt base64>$<hash base64>``. Pure and synchronous: callers run it in
a thread.
"""

import base64
import hashlib
import hmac
import re
import secrets
import string
from dataclasses import dataclass
from functools import cache

SCHEME = "scrypt"
SALT_BYTES = 16
HASH_BYTES = 32
MAX_MEMORY = 256 * 1024 * 1024  # bound accepted when reading a stored hash
GENERATED_LENGTH = 24
GENERATED_ALPHABET = string.ascii_letters + string.digits
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 1024
# Account names travel in HTTP Basic: no colon, no control character.
USERNAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass(frozen=True)
class ScryptParameters:
    n: int
    r: int
    p: int

    @property
    def memory(self) -> int:
        """Bytes used by one derivation (OpenSSL: 128 r N for V, plus 128 r p for the blocks)."""
        return 128 * self.r * (self.n + self.p)


DEFAULT_PARAMETERS = ScryptParameters(n=2**15, r=8, p=3)


class InvalidPassword(ValueError):
    pass


def check_password(password: str) -> str:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise InvalidPassword(
            f"a password has {MIN_PASSWORD_LENGTH} to {MAX_PASSWORD_LENGTH} characters"
        )
    if any(not char.isprintable() for char in password):
        raise InvalidPassword("a password cannot contain control characters")
    return password


def generate_password() -> str:
    """24 random letters and digits (about 143 bits)."""
    return "".join(secrets.choice(GENERATED_ALPHABET) for _ in range(GENERATED_LENGTH))


def _derive(password: str, salt: bytes, parameters: ScryptParameters) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=parameters.n,
        r=parameters.r,
        p=parameters.p,
        maxmem=max(MAX_MEMORY, 2 * parameters.memory),
        dklen=HASH_BYTES,
    )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str, parameters: ScryptParameters | None = None) -> str:
    """Parameters: ``DEFAULT_PARAMETERS`` read at call time (tests lower them)."""
    parameters = parameters or DEFAULT_PARAMETERS
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _derive(password, salt, parameters)
    return f"{SCHEME}${parameters.n}${parameters.r}${parameters.p}${_b64(salt)}${_b64(digest)}"


def _parse(stored: str) -> tuple[ScryptParameters, bytes, bytes] | None:
    parts = stored.split("$")
    if len(parts) != 6 or parts[0] != SCHEME:
        return None
    try:
        parameters = ScryptParameters(int(parts[1]), int(parts[2]), int(parts[3]))
        salt, digest = base64.b64decode(parts[4]), base64.b64decode(parts[5])
    except ValueError:
        return None
    if parameters.memory > MAX_MEMORY or parameters.n < 2 or parameters.n & (parameters.n - 1):
        return None
    return parameters, salt, digest


@cache
def _dummy_hash(parameters: ScryptParameters) -> str:
    return hash_password(secrets.token_urlsafe(32), parameters)


def dummy_hash() -> str:
    """A hash nobody knows the password of: an unknown account costs the same time."""
    return _dummy_hash(DEFAULT_PARAMETERS)


def verify_password(password: str, stored: str | None) -> bool:
    """Constant time; ``stored = None`` (unknown account) still runs one full derivation."""
    parsed = _parse(stored) if stored is not None else None
    if parsed is None:
        reference = _parse(dummy_hash())
        if reference is None:  # pragma: no cover - built by this module
            return False
        parameters, salt, digest = reference
        hmac.compare_digest(_derive(password, salt, parameters), digest)
        return False
    parameters, salt, digest = parsed
    return hmac.compare_digest(_derive(password, salt, parameters), digest)
