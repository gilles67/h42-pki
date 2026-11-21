"""Certificate serial numbers."""

from cryptography import x509


def new_serial_hex() -> str:
    """Return a fresh random 159-bit serial number as lowercase hex (B1)."""
    return format(x509.random_serial_number(), "x")
