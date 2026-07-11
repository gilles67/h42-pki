from tortoise import fields
from tortoise.models import Model

from tortoise.contrib.pydantic import pydantic_model_creator
from pydantic import ConfigDict, SkipValidation, field_serializer

from cryptography import x509
from cryptography.x509.extensions import ReasonFlags

from enum import IntEnum


class Certificate(Model):
    model_config = ConfigDict(from_attributes=True, arbitrary_types_allowed=True)

    uid = fields.UUIDField(primary_key=True)
    sn = fields.BigIntField(unique=True, default=x509.random_serial_number())

    subject = fields.JSONField()
    extension = fields.JSONField()

    key = fields.BinaryField(null=True)
    csr = fields.BinaryField(null=True)
    crt = fields.BinaryField(null=True)

    revoked_flag = fields.CharEnumField(ReasonFlags,null=True)

    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    revoked_at = fields.DatetimeField(null=True)
    expire_at = fields.DatetimeField(null=True)

    class Meta: 
        table = "pki_certificate"



class Authority(Model): 
    model_config = ConfigDict(from_attributes=True, arbitrary_types_allowed=True)

    uid = fields.UUIDField(primary_key=True)
    external_id = fields.UUIDField(null=True)
    
    fqdn = fields.CharField(null=True, unique=True, max_length=128)
    certificate = fields.UUIDField(primary_key=True)

    

    class Meta: 
        table = "pki_authority"
