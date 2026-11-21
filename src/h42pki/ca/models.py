from tortoise import fields
from tortoise.models import Model
from uuid import UUID

from tortoise.contrib.pydantic import pydantic_model_creator
from pydantic import ConfigDict, SkipValidation, field_serializer, BaseModel

from cryptography import x509
from cryptography.x509.extensions import ReasonFlags

from enum import StrEnum

from .pki_models import Subject, Extension

class PrivateKeyType(StrEnum):
    RSA2048 = 'rsa_2048'
    RSA3072 = 'rsa_3072'
    RSA4096 = 'rsa_4096'

    @classmethod
    def getsize(cls, key_type: str):
        return int(key_type.split("_")[1])

    @classmethod
    def gettype(cls, key_type:str):
        return key_type.split("_")[0]


class Certificate(Model):
    model_config = ConfigDict(from_attributes=True, arbitrary_types_allowed=True)

    uid = fields.UUIDField(primary_key=True)
    sn = fields.CharField(unique=True, default=x509.random_serial_number(), max_length=48)

    subject = fields.JSONField(field_type=Subject)
    extension = fields.JSONField(field_type=Extension)

    key = fields.BinaryField(null=True)
    csr = fields.BinaryField(null=True)
    crt = fields.BinaryField(null=True)

    revoked_flag = fields.CharEnumField(ReasonFlags,null=True)

    privatekey = fields.UUIDField(null=True)

    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    signed_at = fields.DatetimeField(null=True)
    expire_at = fields.DatetimeField(null=True)
    revoked_at = fields.DatetimeField(null=True)
    
    signed_by = fields.UUIDField(null=True)

    class Meta: 
        table = "pki_certificate"


class Authority(Model): 
    model_config = ConfigDict(from_attributes=True, arbitrary_types_allowed=True)

    uid = fields.UUIDField(primary_key=True)
    certificate = fields.UUIDField(null=True)

    external_id = fields.UUIDField(null=True)
    fqdn = fields.CharField(null=True, unique=True, max_length=128)

    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta: 
        table = "pki_authority"

class PrivateKey(Model):
    model_config = ConfigDict(from_attributes=True, arbitrary_types_allowed=True)
    uid = fields.UUIDField(primary_key=True)
    key_type = fields.data.CharEnumField(PrivateKeyType, default=PrivateKeyType.RSA4096)

    key = fields.BinaryField(null=True)

    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta: 
        table = "pki_privatekey"


PrivateKeyCreateMixin = pydantic_model_creator(PrivateKey,exclude=("uid","key","created_at", "updated_at",))
PrivateKeyOutput = pydantic_model_creator(PrivateKey,exclude=("key",))

CertificateCreateMixin = pydantic_model_creator(Certificate,exclude=("uid","sn","key","csr","crt","revoked_flag","created_at","updated_at","signed_at","expire_at","revoked_at","signed_by",))