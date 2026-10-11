from pydantic import BaseModel, Field
from cryptography import x509
from cryptography.x509.oid import NameOID


SUBJET_MAPPER = {
    "CountryName": NameOID.COUNTRY_NAME,
    "ProvinceName": NameOID.STATE_OR_PROVINCE_NAME,
    "LocalityName": NameOID.LOCALITY_NAME,
    "OrganizationName": NameOID.ORGANIZATION_NAME,
    "OrganizationUnitName": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CommonName": NameOID.COMMON_NAME,
    "Email": NameOID.EMAIL_ADDRESS,
}


class Subject(BaseModel):
    CountryName: str
    ProvinceName: str
    LocalityName: str
    OrganizationName: str
    OrganizationUnitName: str
    CommonName: str
    Email: str

    def x509_subject(self):
        attributes = []
        for (field, value) in self: 
            attributes.append(x509.NameAttribute(SUBJET_MAPPER[field], value))
        return x509.Name(attributes)


class X509BasicConstraints(BaseModel):
    CertificateAuthority: bool = Field(default=False)
    PathLength: int = Field(default=0)

class X509KeyUsage(BaseModel):
    DigitalSignature: bool = Field(default=False)
    ContentCommitment: bool = Field(default=False) 
    KeyEncipherment: bool = Field(default=False)
    DataEncipherment: bool = Field(default=False)
    KeyAgreement: bool = Field(default=False)
    KeyCertSign: bool = Field(default=False)
    CrlSign: bool = Field(default=False)
    EncipherOnly: bool = Field(default=False)
    DecipherOnly: bool = Field(default=False)

class X509ExtendedKeyUsage(BaseModel):
    ServerAuthentication: bool = Field(default=False)
    ClientAuthentication: bool = Field(default=False)
    CodeSigning: bool = Field(default=False)
    EmailProtection: bool = Field(default=False) 
    TimeStamping: bool = Field(default=False)


class Extension(BaseModel):
    BasicConstraints: X509BasicConstraints | None = None
    KeyUsage: X509KeyUsage | None = None
    ExtendedKeyUsage: X509ExtendedKeyUsage | None = None


    def append_extension(self, cert): 
        if self.BasicConstraints is not None:
            cert = cert.add_extension(
                x509.BasicConstraints(
                    ca=self.BasicConstraints.CertificateAuthority,
                    path_length=self.BasicConstraints.PathLength
                ),
                critical=True
            )
        if self.KeyUsage is not None:
            cert = cert.add_extension(
                x509.KeyUsage(
                    digital_signature=self.KeyUsage.DigitalSignature,
                    content_commitment=self.KeyUsage.ContentCommitment,
                    key_encipherment=self.KeyUsage.KeyEncipherment,
                    data_encipherment=self.KeyUsage.DataEncipherment,
                    key_agreement=self.KeyUsage.KeyAgreement,
                    key_cert_sign=self.KeyUsage.KeyCertSign,
                    crl_sign=self.KeyUsage.CrlSign,
                    encipher_only=self.KeyUsage.EncipherOnly,
                    decipher_only=self.KeyUsage.DecipherOnly
                ),
                critical=True
            )
        return cert