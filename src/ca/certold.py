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
