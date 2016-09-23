from collections import namedtuple
import eccsnacks
from libnacl import \
    crypto_box_keypair as x25519_keypair, \
    crypto_box_beforenm as x25519_dh, \
    crypto_hash_sha256 as sha256_hash, \
    crypto_hash_sha512 as sha512_hash, \
    crypto_generichash as blake2b_hash


KeyPair = namedtuple('KeyPair', ('public_key', 'private_key'))

class Singleton:

    __instance = None

    def __new__(self, *args, **kwargs):
        """Return instance of class, creating if necessary"""
        if self.__instance is None:
            self.__instance = object.__new__(self, *args, **kwargs)
        return self.__instance

    def __call__(self):
        raise TypeError('This must will be called only on new.')


class HASH(Singleton):
    hash_length = None
    block_length = None

    def HASH(self, inputbytes):
        raise NotImplementedError

    def hmac_hash(self, key, data):
        if len(key) < self.block_length:
            key = key.rjust(self.block_length, b'\x00')
        else:
            key = self.HASH(key)

        opad = bytes(0x5c ^ byte for byte in key)
        ipad = bytes(0x36 ^ byte for byte in key)
        return self.HASH(opad + self.HASH(ipad + data))


class BLAKE2b(HASH):
    HASHLEN = 64
    BLOCKLEN = 128
    NAME = b'BLAKE2b'
    HASH = blake2b_hash

class BLAKE2s(HASH):
    HASHLEN = 32
    BLOCKLEN = 64
    HASH = b'BLAKE2s'

class SHA256(HASH):
    HASHLEN = 32
    BLOCKLEN = 64
    NAME = b'SHA256'
    HASH = sha256_hash


class SHA512(HASH):
    HASHLEN = 64
    BLOCKLEN = 128
    NAME = b'SHA512'
    HASH = sha512_hash

# Base class for DH(Diffie - Helman), this will be inherited by other cipher functions
# and these functions will be called from their respective classes.

class DH(Singleton):
    DHLEN = None
    NAME = b''

    @classmethod
    def GENERATE_KEYPAIR(self):
        # will be overriden by their respective class, else Error.
        raise NotImplementedError

    @classmethod
    def DH(self, keypair, public_key):
        # will be overriden by their respective class calling NaCl function, else Error.
        raise NotImplementedError


# implemetation of X25519 curve. Inherits DH class.
# Ref : 10.1. The 25519 DH functions
class X25519(DH):
    DHLEN = 32
    NAME = b'25519'

    @classmethod
    def GENERATE_KEYPAIR(self):
        return KeyPair(*x25519_keypair())

    @classmethod
    def DH(self, keypair, public_key):
        return x25519_dh(public_key, keypair.private_key)


# implemetation of X25519 curve. Inherits DH class.
# Ref : 10.2. The 448 DH functions
if __name__ == '__main__':
    class X448(DH):
        DHLEN = 56
        NAME = b'448'

        # Will be wrapping eccsnacks for implementation
