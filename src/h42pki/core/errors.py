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


class InvalidSubject(InvalidRequest):
    title = "Invalid Subject"


class InvalidSan(InvalidRequest):
    title = "Invalid Subject Alternative Name"


class InvalidCsr(InvalidRequest):
    title = "Invalid CSR"


class ProfileViolation(InvalidRequest):
    title = "Profile Violation"


class PathLengthExceeded(InvalidRequest):
    title = "Path Length Exceeded"


class InvalidPublicBaseUrl(InvalidRequest):
    title = "Invalid Public Base URL"


class InvalidAuthorityName(InvalidRequest):
    title = "Invalid Authority Name"


class InvalidHostname(InvalidRequest):
    title = "Invalid Hostname"


class InvalidNetwork(InvalidRequest):
    title = "Invalid Network"
