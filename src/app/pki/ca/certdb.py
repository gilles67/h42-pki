import sys, os, logging, tomllib, json, 
from cryptography import x509

CERTDB_CONFIGFILE = os.environ.get("H42_PKI_CERTDB", "/app/config/ca.toml")
logger = logging.getLogger(__name__)


class certdbConf: 
    self._data = {}
    self._configfile = None
    def __init__(self, configfile=CA_CONFIGFILE):
        self._configfile = configfile
        self.load()
        logger.info("Load configuration from : {}".format(configfile))
    
    def load(self): 
        if (os.path.exits(self._configfile)):
            self._data = tomllib.load(f)




class certdbFolder:
    _db = None
    _name = None
    _path = None
    def __init__(self, db, name):
        self._db = db
        self._name = name

class certdbDocument:
    _folder = None
    _serial = None
    _filename = None

    def __init__(self, folder, serial):



class certdb:
    _conf = None
    _path = None
    _inbox = None
    _signed = None
    _expired = None
    _revoked = None

    def __init__(self):
        self._conf = certdbConf()




# class CACertificateDoc:
#     def __init__(self, serial=x509.random_serial_number()):





if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, encoding='utf-8', level=logging.DEBUG)
    db = certdb()

