import sys, os, os.path, tomllib
CA_CONFIGFILE = os.environ.get("H42_PKI_CA_CONFIGFILE", "/app/config/ca.toml")

class CACertificateConf: 
    self._data = {}
    self._configfile = None
    def __init__(self, configfile=CA_CONFIGFILE):
        self._configfile = configfile
        self.load()
    
    def load(self): 
        if (os.path.exits(self._configfile)):
            self._data = tomllib.load(f)
