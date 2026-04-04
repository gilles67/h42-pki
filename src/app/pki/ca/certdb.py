import sys, os, logging, tomllib, json, datetime
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
            json.dump(self.model_dump(mode='json'), f)
            f.close()

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
    model: str

    @property
    def csr(self):
        if self.__csr_object == None:
            self.__csr_object = x509.load_pem_x509_csr(bytes(self.csr_data, DEFAULT_ENCODING))
        return self.__csr_object

    


class Certificate(CertModel):
    crt_data: str | None = None
    crt_type: CertType | None = None
    key_data: str | None = None
    status: int = 0
    
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
            self.__key_object = serialization.load_pem_private_key(bytes(self.key_data, DEFAULT_ENCODING), password=self.__key_passphare)
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
        __requests = CertFolder(os.path.join(path, "Request"))
        __certificates = CertFolder(os.path.join(path, "Certificate"))
        
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



def _write_binary(filename, bdata):
    with open(filename, "wb") as f:
        f.write(bdata)
        f.close()

def _read_binary(filename):
    data = None
    with open(filename, "rb") as f:
        data = f.read()
        f.close()
    return data

def _generate_rsa(size, filename, passphrase):
    key = rsa.generate_private_key(public_exponent=65537, key_size=size)
    _write_binay(filename, key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    ))
    return key

def _load_rsa(filename, passphrase):
    key = serialization.load_pem_private_key(_read_binary(filename), password=passphrase)
    if not isinstance(key, rsa.RSAPublicKey):
        Exception("File {} not contains RSA key !".format(filename))
    return key


def _subject_generator(conf, item="Authority", commonField="CommonName"):
    attributes = []
    if conf.get(item,"CountryName"):
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, conf.get(item,"CountryName")))
    if conf.get(item,"ProvinceName"):
        attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, conf.get(item,"ProvinceName")))
    if conf.get(item,"LocalityName"):
        attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, conf.get(item,"LocalityName")))
    if conf.get(item,"OrganizationName"):
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, conf.get(item,"OrganizationName")))
    if conf.get(item,"OrganizationUnitName"):
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, conf.get(item,"OrganizationUnitName")))

    if conf.get(item, commonField):
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, conf.get(item,commonField)))

    return x509.Name(attributes)






class certdbFolder:
    _db = None
    _name = None
    _path = None
    def __init__(self, db, name):
        self._db = db
        self._name = name
        self._path = os.path.join(db.path, name)
        if os.path.isdir(self._path):
            logger.debug("Database folder {} : {} exists.".format(name, self._path))
        else:
            logger.debug("Database folder {} : {} not exists, creating ...".format(name, self._path))
            os.makedirs(self._path)

class certdbDocument:
    _folder = None
    _serial = None
    _filename = None

    def __init__(self, folder, serial):
        self._folder = folder



class certdb:
    _conf = None
    _path = None
    _inbox = None
    _signed = None
    _expired = None
    _revoked = None
    _pkey_path = None
    _pkey = None
    _cert_path = None
    _cert = None

    def __init__(self):
        self._conf = certdbConf()
        self._path = self._conf.get("Authority", "DataPath", default="/app/config/ca")
        if os.path.isdir(self._path):
            logger.debug("Database path: {} exists.".format(self._path))
        else:
            logger.debug("Database path: {} not exists, creating ...".format(self._path))
            os.makedirs(self._path)
        
        self._inbox = certdbFolder(self, "inbox")
        self._signed = certdbFolder(self, "signed")
        self._expired = certdbFolder(self, "expired")
        self._revoked = certdbFolder(self, "revoked")

        self._pkey_path = self._conf.get("PrivateKey", "KeyPath", default=os.path.join(self._path, "private", "key.pem"))
        self._cert_path = self._conf.get("Authority", "CertPath", default=os.path.join(self._path, "cert.pem"))

    @property
    def conf(self):
        return self._conf

    @property
    def path(self):
        return self._path 

    def receiveCsr(self, data):
        sn = x509.random_serial_number()
        csr_path = os.path.join(self._path, "inbox", str(sn) + ".csr")
        _write_binary(csr_path, data)
        csr = x509.load_pem_x509_csr(data)
        logger.debug("New CSR: {}, Subject: {}.".format(csr_path, csr.subject))
        return sn

    def signCsr(self, sn):
        csr_path = os.path.join(self._path, "inbox", str(sn) + ".csr")
        if not os.path.isfile(csr_path):
            raise FileNotFoundError(csr_path)
        csr = x509.load_pem_x509_csr(_read_binary(csr_path))

        cert = x509.CertificateBuilder()
        cert = cert.subject_name(csr.subject)
        cert = cert.public_key(csr.public_key())
        for ext in csr.extensions:
            cert = cert.add_extension(ext.value, critical=False)
        cert = cert.issuer_name(self._cert.subject)
        cert = cert.serial_number(sn)
        cert = cert.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        cert = cert.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=self._conf.get("Signing","ExpireOffset", default=365)))

        cert = cert.add_extension(x509.BasicConstraints(ca=False, path_length=None),  critical=True)
        cert = cert.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        cert = cert.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        cert = cert.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(self._cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False)

        if self._conf.get("Authority", "FQDN"):
            cert = cert.add_extension(x509.CRLDistributionPoints([
                x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier("http://{}/dist.crl".format(self._conf.get("Authority", "FQDN")))], relative_name=None, crl_issuer=None, reasons=None)
            ]), critical=False)
            cert = cert.add_extension(x509.AuthorityInformationAccess([
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("http://{}/cert.pem".format(self._conf.get("Authority", "FQDN"))))
            ]), critical=False)

        cert_path = os.path.join(self._path, "signed", str(sn) + ".pem")
        cert = cert.sign(self._pkey, hashes.SHA256())

        _write_binary(cert_path, cert.public_bytes(serialization.Encoding.PEM))

        return cert

    def generatePrivateKey(self, size=4096):

        if os.path.isfile(self._pkey_path): 
            logger.debug("Private Key: {} exists.".format(self._pkey_path))
            self.loadPrivateKey()
            return
        else:
            logger.debug("Private Key: {} not exists. Generating ...".format(self._pkey_path))

        self._pkey = _generate_rsa(4096, self._pkey_path, bytes(self._conf.get("PrivateKey","Passphrase"), "utf-8"))

    def loadPrivateKey(self):
        if not os.path.isfile(self._pkey_path): 
            raise FileNotFoundError(self._pkey_path)

        with open(self._pkey_path, "rb") as f:
            self._pkey = serialization.load_pem_private_key(f.read(), password=bytes(self._conf.get("PrivateKey","Passphrase"), "utf-8"))
            f.close()

        if isinstance(self._pkey, rsa.RSAPrivateKey):
            logger.debug("Private Key: {} loaded.".format(self._pkey_path))
        else:
            raise Exception("No key loaded.")

    def generateCertificate(self):
        if os.path.isfile(self._cert_path):
            self._cert = x509.load_pem_x509_certificate(_read_binary(self._cert_path))
            return

        logger.debug("Authority Certificate: {} not exist. Creating...".format(self._cert_path))

        ## Subject
        subject = issuer = _subject_generator(self._conf)
        logger.debug("Authority Subject: {}".format(subject))

        ## Serial Number 
        sn = x509.random_serial_number()

        ## Cretificate 
        cert = x509.CertificateBuilder()
        cert = cert.subject_name(subject)
        cert = cert.issuer_name(issuer)
        cert = cert.public_key(self._pkey.public_key())
        cert = cert.serial_number(sn)
        cert = cert.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        cert = cert.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=self._conf.get("Authority","ExpireOffset", default=1461)))
        cert = cert.add_extension(x509.BasicConstraints(ca=True, path_length=self._conf.get("Authority","CALength")), critical=True)
        cert = cert.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(self._pkey.public_key()), critical=False)

        self._cert = cert.sign(self._pkey, hashes.SHA256())

        with open(self._cert_path, "wb") as f:
             f.write(self._cert.public_bytes(serialization.Encoding.PEM))
             f.close()

def generateServiceRequest(conf):
    pkey_file = '/app/config/services/key.pem'
    pkey = None
    if os.path.isfile(pkey_file):
        pkey = _load_rsa(pkey_file, bytes(conf.get("Services","Passphrase"), "utf-8"))
    else:
        pkey = _generate_rsa(2048, '/app/config/services/key.pem', bytes(conf.get("Services","Passphrase"), "utf-8"))

    ## Subject
    subject = _subject_generator(conf, commonField="FQDN")

    # CSR
    csr = x509.CertificateSigningRequestBuilder()
    csr = csr.subject_name(subject)
    csr = csr.add_extension(x509.SubjectAlternativeName([x509.DNSName(conf.get("Authority", "FQDN"))]), critical=False)
    
    csr = csr.sign(pkey, hashes.SHA256())
    
    return csr.public_bytes(serialization.Encoding.PEM)


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, encoding='utf-8', level=logging.DEBUG)
    db = CertDatabase()
    if db.authority == None:
        auth = Certificate()
        auth.crt_type = CertType.RootCA
        auth.SetKeyPassphare(db.conf.get("Authority", "KeyPassphrase", default=None))
        auth.GenerateKey(KeyType.RSA4096)
        auth.GenerateSelfSign(db.conf.get("Authority"), int(db.conf.get("Authority", "ExpireOffset", default=5844)), length=int(db.conf.get("Authority", "Length", default=0)))
        auth.write(os.path.join(db.path, "Authority.json"))
