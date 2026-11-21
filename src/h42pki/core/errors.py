"""Errors raised by ``h42pki.core``. Messages never contain key material or passphrases."""

from h42pki.errors import H42Error, InvalidRequest


class UnsupportedAlgorithm(InvalidRequest):
    title = "Unsupported Algorithm"


class InvalidPassphrase(H42Error):
    """A stored key cannot be decrypted: server-side misconfiguration, hence 500."""

    title = "Key Decryption Failed"


class InvalidExtensions(InvalidRequest):
    title = "Invalid Extensions"


class InvalidValidity(InvalidRequest):
    title = "Invalid Validity"


class NotARootCA(InvalidRequest):
    title = "Not A Root CA"
