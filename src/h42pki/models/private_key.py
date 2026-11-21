"""Private keys held by this container."""

from enum import StrEnum

from tortoise import fields

from h42pki.models.base import TimestampedModel


class KeyAlgorithm(StrEnum):
    # EC and Ed25519 come with B8 (lot 4).
    RSA2048 = "rsa2048"
    RSA3072 = "rsa3072"
    RSA4096 = "rsa4096"

    @property
    def key_size(self) -> int:
        return int(self.value.removeprefix("rsa"))


class KeyBackend(StrEnum):
    SOFTWARE = "software"
    PKCS11 = "pkcs11"


class PrivateKey(TimestampedModel):
    algorithm = fields.CharEnumField(KeyAlgorithm, max_length=16)
    backend = fields.CharEnumField(KeyBackend, default=KeyBackend.SOFTWARE, max_length=16)
    # Encrypted with the CA passphrase; still TraditionalOpenSSL PEM until B18 (lot 4).
    # Never returned by the API.
    encrypted_key = fields.BinaryField()
    public_key_der = fields.BinaryField()

    class Meta:
        table = "private_key"
