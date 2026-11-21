import json 
import os
import datetime
from .models import PrivateKeyCreateMixin, PrivateKeyOutput, PrivateKeyType, PrivateKey, CertificateCreateMixin, Certificate
from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from uuid import UUID

DEFAULT_ENCODING = "utf-8"

class PkiConfiguration:
    def __init__(self, data):
        self.data = data

    @property
    def passphrase(self):
        return bytes(self.data["passphrase"],DEFAULT_ENCODING)

    @classmethod
    def load(cls, filename="config/pki.json"):
        st = os.stat(filename)
        if oct(st.st_mode) != 0o100600:
            Exception("Connfiguration file config/pki.json wrong premission set 600 !")
        with open(filename) as file:
            return cls(json.load(file))
    

class PkiPrivateKey: 

    @classmethod
    async def generate(cls, query: PrivateKeyCreateMixin):
        config = PkiConfiguration.load()

        if PrivateKeyType.gettype(query.key_type) == "rsa":
            pvkey = rsa.generate_private_key(public_exponent=65537, key_size=PrivateKeyType.getsize(query.key_type))
            key_data = pvkey.private_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PrivateFormat.TraditionalOpenSSL,
              encryption_algorithm=serialization.BestAvailableEncryption(config.passphrase)  
            )
        
        return await PrivateKey.create(key_type=query.key_type, key=key_data)


    @classmethod
    async def load_key(cls, key_id: UUID):
        config = PkiConfiguration.load()

        datakey = await PrivateKey.get(uid=key_id)
        pvkey = serialization.load_pem_private_key(datakey.key, password=config.passphrase)

        return (datakey, pvkey)


    @classmethod
    async def delete_key(cls, key_id: UUID):
        datakey = await PrivateKey.get(uid=key_id)
        datakey.delete()
        return datakey


class PkiCertificate: 

    @classmethod
    async def generate(cls, query: CertificateCreateMixin):
        cert = await Certificate.create(
            privatekey = query.privatekey,
            subject = query.subject,
            extension = query.extension
        )
        return cert

    @classmethod
    async def self_sign(cls, cert_id: UUID):
        cert = await Certificate.get(uid=cert_id)
        (datakey, pvkey) = await PkiPrivateKey.load_key(cert.privatekey)
        days = 3653
        expire_at = datetime.datetime.utcnow() + datetime.timedelta(days=days)

        subject = issuer = cert.subject.x509_subject()
        x509_cert = x509.CertificateBuilder()
        x509_cert = x509_cert.subject_name(subject)
        x509_cert = x509_cert.issuer_name(issuer)

        x509_cert = x509_cert.public_key(pvkey.public_key())
        x509_cert = x509_cert.serial_number(int(cert.sn))
        x509_cert = x509_cert.not_valid_before(datetime.datetime.utcnow())
        x509_cert = x509_cert.not_valid_after(expire_at)

        x509_cert = cert.extension.append_extension(x509_cert)

        x509_cert = x509_cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(pvkey.public_key()), critical=False)

        x509_cert_sign = x509_cert.sign(pvkey, hashes.SHA512())

        cert.crt = x509_cert_sign.public_bytes(serialization.Encoding.PEM)
        cert.expire_at = expire_at
        cert.key = pvkey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        await cert.save()

        return cert

    @classmethod
    async def get_certificate(cls, cert_id: UUID):
        cert = await Certificate.get(uid=cert_id)
        return cert