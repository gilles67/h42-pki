"""Private keys held by this container."""

from enum import StrEnum

from tortoise import fields

from h42pki.core.keys import KeyAlgorithm
from h42pki.models.base import TimestampedModel


class KeyBackend(StrEnum):
    SOFTWARE = "software"
    PKCS11 = "pkcs11"


class PrivateKey(TimestampedModel):
    algorithm = fields.CharEnumField(KeyAlgorithm, max_length=16)
    backend = fields.CharEnumField(KeyBackend, default=KeyBackend.SOFTWARE, max_length=16)
    # Encrypted PKCS#8 DER (h42pki.core.keys.serialize_encrypted). Never returned by the API.
    encrypted_key = fields.BinaryField()
    public_key_der = fields.BinaryField()

    class Meta:
        table = "private_key"
