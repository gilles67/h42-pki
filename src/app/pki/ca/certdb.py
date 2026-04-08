import sys, os, logging, tomllib, json, datetime, requests
from pydantic import BaseModel
from enum import IntEnum, Enum
from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger("certdb")

CERTDB_CONFIGFILE = os.environ.get("H42_PKI_CERTDB", "/app/config/ca.toml")

DEFAULT_ENCODING = "utf-8"
SUBJET_MAPPER = {
    "C": NameOID.COUNTRY_NAME,
    "CountryName": NameOID.COUNTRY_NAME,
    "S": NameOID.STATE_OR_PROVINCE_NAME,
    "ProvinceName": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "LocalityName": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OrganizationName": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "OrganizationUnitName": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
    "CommonName": NameOID.COMMON_NAME,
    "E": NameOID.EMAIL_ADDRESS,
    "Email": NameOID.EMAIL_ADDRESS,
    "DN": NameOID.DN_QUALIFIER
}

class KeyType(IntEnum): 
    RSA2048 = 2048
    RSA4096 = 4096

class CertType(IntEnum):
    RootCA = 1
    IntermediateCA = 2
    Server = 3
    Client = 4

class CertModel(BaseModel):
    sn: int = x509.random_serial_number()
    def write(self, filename):
        with open(filename, "w") as f:
            json.dump(self.dict(), f)
            f.close()
        return self.sn

    def dict(self):
        return self.model_dump(mode='json')

    @classmethod
    def load(cls, filename):
        obj = None
        with open(filename, "r") as f:
            obj = cls.model_validate(json.load(f))
            f.close()
        return obj

    def subjectGenerator(self, subject=[]): 
        subject_list = []
        if type(subject) is dict: 
            for item in subject:
                if item in SUBJET_MAPPER:
                    subject_list.append((item, subject[item]))
        else:
            subject_list = subject

        attributes = []
        for (name, value) in subject_list:
            if name in SUBJET_MAPPER: 
                attr = SUBJET_MAPPER[name]
                attributes.append(x509.NameAttribute(attr, value))
            else:
                logger.debug("[subjectGenerator] Field:{} with value {} not exits in SUBJET_MAPPER".format(name, value))
        return x509.Name(attributes)


class Request(CertModel):
    csr_data: str | None = None
    csr_type: CertType | None = None
    crt_model: str | None = None
    __csr_object = None

    @property
    def csr(self):
        if self.__csr_object == None:
            self.__csr_object = x509.load_pem_x509_csr(bytes(self.csr_data, DEFAULT_ENCODING))
        return self.__csr_object

    def GenerateRequest(self, subject, pkey, length=0):
        csr = x509.CertificateSigningRequestBuilder()
        csr = csr.subject_name(self.subjectGenerator(subject))

        if self.csr_type == CertType.IntermediateCA:
            csr = csr.add_extension(x509.BasicConstraints(ca=True, path_length=length), critical=True)
            csr = csr.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        
        if self.csr_type == CertType.Server or self.csr_type == CertType.Client:
            csr = csr.add_extension(x509.BasicConstraints(ca=False), critical=True)
            csr = csr.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)

        if self.csr_type == CertType.Server:
            csr = csr.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        
        if self.csr_type == CertType.Client:
            csr = csr.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)

        csr = csr.sign(pkey, hashes.SHA256())
        self.csr_data = csr.public_bytes(serialization.Encoding.PEM).decode(DEFAULT_ENCODING)


class Certificate(CertModel):
    crt_data: str | None = None
    crt_type: CertType | None = None
    key_data: str | None = None
    status: int = 0
    __crt_object = None
    __key_object = None
    
    @property
    def crt(self):
        if self.__crt_object == None:
            self.__crt_object = x509.load_pem_x509_certificate(bytes(self.crt_data, DEFAULT_ENCODING))
        return self.__crt_object

    @property
    def key(self):
        if self.key_data == None:
            return None
        if self.__key_object == None: 
            self.__key_object = serialization.load_pem_private_key(bytes(self.key_data, DEFAULT_ENCODING), password=bytes(self.__key_passphare,DEFAULT_ENCODING))
        return self.__key_object

    def SetKeyPassphare(self, passphrase=None):
        self.__key_passphare = passphrase
        logger.debug("Set Passphrase: {}".format(passphrase))

    def GenerateKey(self, key_type: KeyType = KeyType.RSA4096):
        if key_type == KeyType.RSA4096 or key_type == KeyType.RSA2048:
           self.__key_object = rsa.generate_private_key(public_exponent=65537, key_size=int(key_type))

        self.key_data = self.__key_object.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(bytes(self.__key_passphare, DEFAULT_ENCODING)),
        ).decode(DEFAULT_ENCODING)

    def GenerateSelfSign(self, subject, days, length = 0):
        subject = issuer = self.subjectGenerator(subject)
        cert = x509.CertificateBuilder()
        cert = cert.subject_name(subject)
        cert = cert.issuer_name(issuer)
        
        cert = cert.public_key(self.key.public_key())
        cert = cert.serial_number(self.sn)
        cert = cert.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        cert = cert.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days))

        if self.crt_type == CertType.RootCA or self.crt_type == CertType.IntermediateCA:
            cert = cert.add_extension(x509.BasicConstraints(ca=True, path_length=length), critical=True)
            cert = cert.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        
        if self.crt_type == CertType.Server or self.crt_type == CertType.Client:
            cert = cert.add_extension(x509.BasicConstraints(ca=False), critical=True)
            cert = cert.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)

        if self.crt_type == CertType.Server:
            cert = cert.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        
        if self.crt_type == CertType.Client:
            cert = cert.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)

        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)

        self.__crt_object = cert.sign(self.key, hashes.SHA512())
        self.crt_data = self.__crt_object.public_bytes(serialization.Encoding.PEM).decode(DEFAULT_ENCODING)

    def GenerateRequest(self, subject, model="IntermediateCA", length=0): 
        csr = Request()
        csr.sn = self.sn
        csr.csr_type = self.crt_type
        csr.crt_model = model
        csr.GenerateRequest(subject, self.key, length)
        return csr

    def SignRequest(self, req, days, fqdn = None):
        csr = req.csr
        cert = x509.CertificateBuilder()
        cert = cert.subject_name(csr.subject)
        cert = cert.public_key(csr.public_key())
        for ext in csr.extensions:
            cert = cert.add_extension(ext.value, critical=False)
        cert = cert.issuer_name(self.crt.subject)
        cert = cert.serial_number(req.sn)
        cert = cert.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        cert = cert.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days))

        # cert = cert.add_extension(x509.BasicConstraints(ca=False, path_length=None),  critical=True)
        # cert = cert.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        # cert = cert.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)

        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        cert = cert.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(self.crt.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False)

        if fqdn:
            cert = cert.add_extension(x509.CRLDistributionPoints([
                x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier("http://{}/dist.crl".format(fqdn))], relative_name=None, crl_issuer=None, reasons=None)
            ]), critical=False)
            cert = cert.add_extension(x509.AuthorityInformationAccess([
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("http://{}/cert.pem".format(fqdn)))
            ]), critical=False)

        cert = cert.sign(self.key, hashes.SHA256())

        crt = Certificate()
        crt.sn = req.sn
        crt.crt_data = cert.public_bytes(serialization.Encoding.PEM).decode(DEFAULT_ENCODING)
        crt.crt_type = req.csr_type

        return crt



class CertConfiguration(): 
    _data = {}
    def __init__(self, configfile=CERTDB_CONFIGFILE):
        self.load(configfile)
        logger.info("Load configuration from : {}".format(configfile))
    
    def load(self, filename): 
        if (os.path.exists(filename)):
            with open(filename, 'rb') as f:
                self._data = tomllib.load(f)
                f.close()
        else:
            raise FileNotFoundError(filename)

    def get(self, *keys, default=None):
        nested_data = self._data
        for key in keys:
            if key in nested_data: 
                nested_data = nested_data[key]
            else:
                nested_data = default
                break
        return nested_data


class CertFolder():
    __path = None
    def __init__(self, path):
        self.__path = path
        if os.path.isdir(self.__path):
            logger.debug("Folder path: {} exists.".format(self.__path))
        else:
            logger.debug("Folder path: {} not exists, creating ...".format(self.__path))
            os.makedirs(self.__path)
    @property
    def path(self):
        return self.__path

    def save(self, ins):
        return ins.write(os.path.join(self.path, str(ins.sn) + ".json"))
    
    def load(self, obj, sn):
        return obj.load(os.path.join(self.path, str(sn) + ".json"))


class CertDatabase(CertFolder):
    __conf = None
    __requests = None
    __certificates = None
    __authority = None

    def __init__(self):
        self.__conf = CertConfiguration()
        path = self.conf.get("Authority", "DataPath", default="/app/config/ca")
        super().__init__(path)
        
        # Folders Request & Certificate
        self.__requests = CertFolder(os.path.join(path, "Request"))
        self.__certificates = CertFolder(os.path.join(path, "Certificate"))
        
        # Authority File 
        authority_file = os.path.join(self.path, "Authority.json")
        if os.path.isfile(authority_file): 
            self.__authority = Certificate.load(authority_file)
            logger.debug("Load authority certificate: {}".format(authority_file))

    @property
    def conf(self):
        return self.__conf

    @property 
    def authority(self):
        return self.__authority

    def ReceiveRequest(self, csr):
        self.__requests.save(csr)
        return csr

    def SignRequest(self, sn):
        csr = self.__requests.load(Request, sn)
        self.authority.SetKeyPassphare(self.conf.get("Authority", "KeyPassphrase", default=None))
        crt = self.authority.SignRequest(csr, self.conf.get("Siging", "ExpireOffset", default=365))
        self.__certificates.save(crt)
        return crt


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, encoding='utf-8', level=logging.DEBUG)
    db = CertDatabase()
    if db.authority == None:
        auth = Certificate()
        auth.SetKeyPassphare(db.conf.get("Authority", "KeyPassphrase", default=None))
        auth.GenerateKey(KeyType.RSA4096)
        if db.conf.get("Authority", "Parent", default="self") == "self":
            auth.crt_type = CertType.RootCA
            auth.GenerateSelfSign(db.conf.get("Authority"), int(db.conf.get("Authority", "ExpireOffset", default=5844)), length=int(db.conf.get("Authority", "Length", default=0)))
        else:
            auth.crt_type = CertType.IntermediateCA
            csr = auth.GenerateRequest(db.conf.get("Authority"), length=int(db.conf.get("Authority", "Length", default=0)))
            req = requests.post(db.conf.get("Authority", "Parent") + "/api/pki/ca/request", json=csr.dict())
            if req.status_code == 200:
                res = requests.get(db.conf.get("Authority", "Parent") + "/api/pki/ca/sign?sn=" + str(auth.sn))
                if res.status_code == 200:
                    print(res.text)
                    auth.crt_data = res.text
                else:
                    raise Exception("Invalide return code durring CRT signing.")
            else:
                raise Exception("Invalide return code durring CSR submission.")
        auth.write(os.path.join(db.path, "Authority.json"))
    
