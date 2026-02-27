import sys, os, logging, tomllib, json
from cryptography import x509

CERTDB_CONFIGFILE = os.environ.get("H42_PKI_CERTDB", "/app/config/ca.toml")
logger = logging.getLogger(__name__)

class certdbConf: 
    _data = {}
    _configfile = None
    def __init__(self, configfile=CERTDB_CONFIGFILE):
        self._configfile = configfile
        self.load()
        logger.info("Load configuration from : {}".format(configfile))
    
    def load(self): 
        if (os.path.exists(self._configfile)):
            with open(self._configfile, 'rb') as f:
                self._data = tomllib.load(f)
                f.close()

    def get(self, *keys, default=None):
        nested_data = self._data
        for key in keys:
            if key in nested_data: 
                nested_data = nested_data[key]
        return nested_data

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
        self._folder = folder



class certdb:
    _conf = None
    _path = None
    _inbox = None
    _signed = None
    _expired = None
    _revoked = None

    def __init__(self):
        self._conf = certdbConf()
        self._path = self._conf.get("Authority", "DataPath", default="/app/config/ca")
        if os.path.isdir(self._path):
            logger.info("Database path: {} exists.".format(self._path))
        else:
            logger.info("Database path: {} not exists, creating ...".format(self._path))
            os.mkdir(self._path)

    @
    def conf(self):
        return self._conf



# class CACertificateDoc:
#     def __init__(self, serial=x509.random_serial_number()):





if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, encoding='utf-8', level=logging.DEBUG)
    db = certdb()

