import os, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes


if not os.path.exists("/app/config/store/key.pem"):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Write our key to disk for safe keeping
    with open("/app/config/store/key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
        f.close()
else:
    print("Private key exists")

key = None
with open("/app/config/store/key.pem", "rb") as f:
    key = serialization.load_pem_private_key(f.read(), b"passphrase")
    f.close()

if key != None: 
    print("Key loaded :  " + str(type(key)))
else:
    exit(1)



subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Grand-Est"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Strasbourg"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Home42"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Home42 Network Services"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Home42 Root CA"),
])


crtdist = x509.DistributionPoint(
    full_name=x509.RFC822Name("http://ca.root.h42"), relative_name=None, crl_issuer=None, reasons=None
)


cert = (x509.CertificateBuilder()
    .issuer_name(issuer)
    .subject_name(subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=2),
        critical=True,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.CRLDistributionPoints([crtdist]),
        critical=False,
    )
).sign(key, hashes.SHA512())

 
with open("/app/config/store/cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
    f.close()
