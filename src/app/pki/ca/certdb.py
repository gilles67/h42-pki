import sys, os, logging
from cryptography import x509

logger = logging.getLogger(__name__)

def _check_folder(path):
    if not os.path.exists(path):
        logger.info('DB Directory {} not exists, creating ...'.format(path))
        os.mkdir(path)

class CACertificateDB:
    _path = None
    _path_inbox = None
    _path_signed = None
    _path_expired = None
    _path_revoked = None

    def __init__(self, path):
        self._path = path 
        self.checkFolders()

    def checkFolders(self):
        _check_folder(self._path)
        
        self._path_inbox = os.path.join(self._path, '_inbox')
        _check_folder(self._path_inbox)
        
        self._path_signed = os.path.join(self._path, 'signed')
        _check_folder(self._path_signed)
        
        self._path_expired = os.path.join(self._path, 'expired')
        _check_folder(self._path_expired)
        
        self._path_revoked = os.path.join(self._path, 'revoked')
        _check_folder(self._path_revoked)

class CACertificateDoc:
    

    def __init__(self, serial=x509.random_serial_number()):





if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, encoding='utf-8', level=logging.DEBUG)
    db = CACertificateDB('/app/config/ca')

