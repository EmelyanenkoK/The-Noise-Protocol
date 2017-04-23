from secp256k1 import PrivateKey, PublicKey
from NoiseTypes import SHA256
import logging
logger=logging.getLogger(__name__)

class Key:
  def __init__(self, key=None):
    if not key:
      self.key=PrivateKey()
    else:
      if type(key)==type(PrivateKey()):
        self.key=key
      elif type(key)==type(Key()):
        self.key=key.key
      else:
        raise
      
  def ecdh(self, public_key):
    pk=public_key.serialize()
    logger.debug("ECDH: %s and our private key"%(hex(int.from_bytes(pk, 'big'))))
    #Bitcoin pubkey format https://bitcoin.org/en/developer-guide#public-key-formats
    #First byte should be 0x02, 0x03 or 0x04, then 32bytes of x-coordinate
    if not pk[0] in [2,3,4]:
      raise Exception('Unknown pubkey format')
    #secp256k1 allows multiplying public key and scalar, so:
    pub=PublicKey(pk, raw=True)
    return pub.ecdh(self.key.private_key)

  def pubkey(self):
    return self.key.pubkey.serialize(compressed=True)
      
  def public_key(self):
    return self.pubkey()

  def public(self):
    return self.pubkey()

  def uncompressed_key(self):
    return self.key.pubkey


class DiffieHellmanSecp256k1:
    NAME=b"secp256k1"
    DHLEN = 32
    Key = Key
    PublicKey = PublicKey

    def __init__(self):
        pass

    @staticmethod
    def generate_keypair():
        return Key()

    @staticmethod
    def DH(key_pair, public_key):
        dh=Key(key_pair).ecdh(public_key)
        #aft_sha=SHA256.hash(dh)
        logger.debug("DH result %s"%(hex(int.from_bytes(dh, 'big')), ))
        return dh # TODO does secp256k1 already make sha256?

    
