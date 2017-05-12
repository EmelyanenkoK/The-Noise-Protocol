from collections import namedtuple
from .errors import HashError, DecryptError



class Singleton(object):
    """Object type that produces exactly one instance"""
    _instance = None

    def __new__(self, *args, **kwargs):
        """Return instance of class, creating if necessary"""
        if self._instance is None:
            self._instance = object.__new__(self, *args)
        return self._instance


class Empty(Singleton):
    """Special empty value
    Use ``empty'' instantiation"""

empty = Empty()





class Cipher(Singleton):
    @classmethod
    def encrypt(self, k, n, ad, plaintext):
        raise NotImplementedError

    @classmethod
    def decrypt(self, k, n, ad, ciphertext):
        raise NotImplementedError

from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305
class ChaChaPoly(Cipher):
    NAME = b'ChaChaPoly'

    @classmethod
    def encrypt(self, k, n, ad, plaintext):
        aead = CHACHA20_POLY1305(k, 'python')
        return aead.seal(n, plaintext, ad)

    @classmethod
    def decrypt(self, k, n, ad, ciphertext):
        aead = CHACHA20_POLY1305(k, 'python')
        res = aead.open(n, ciphertext, ad)
        if res is None:
            raise DecryptError("Tag is invalid")
        return res



import hmac
import hashlib
class Hash(Singleton):
    HASHLEN = None
    BLOCKLEN = None

    @classmethod
    def hash(self, inputbytes):
        raise NotImplementedError

    @classmethod
    def hmac_hash(self, key, data):
        return hmac.new( key, data, hashlib.sha256).digest()

    @classmethod
    def hkdf(self, chaining_key, input_key_material, dhlen=64):
        if len(chaining_key) != self.HASHLEN:
            raise HashError("Incorrect chaining key length")
        if len(input_key_material) not in (0, 32, dhlen):
            raise HashError("Incorrect input key material length")
        temp_key = self.hmac_hash(chaining_key, input_key_material)
        output1 = self.hmac_hash(temp_key, b'\x01')
        output2 = self.hmac_hash(temp_key, output1 + b'\x02')
        return output1, output2


class SHA256(Hash):
    HASHLEN = 32
    BLOCKLEN = 64
    NAME = b'SHA256'
    def hash(x):
        return hashlib.sha256(x).digest()




class NoiseBuffer(object):
    """
    Pre-allocated bytestring buffer with append interface
    Strict mode prevents increasing beyond the original buffer size,
    while non-strict mode permits arbitrary appends.
    When done appending, retrieve final values with bytes(...)
    """
    def __init__(self, nbytes=0, strict=False):
        self.bfr = bytearray(nbytes)
        self.length = 0
        self.strict = strict

    def __len__(self):
        return self.length

    def append(self, val):
        """Append byte string val to buffer
        If the result exceeds the length of the buffer, behavior
        depends on whether instance was initialized as strict.
        In strict mode, a ValueError is raised.
        In non-strict mode, the buffer is extended as necessary.
        """
        new_len = self.length + len(val)
        to_add = new_len - len(self.bfr)
        if self.strict and to_add > 0:
            raise ValueError("Cannot resize buffer")
        self.bfr[self.length:new_len] = val
        self.length = new_len

    def __bytes__(self):
        """Return immutable copy of buffer
        In strict mode, return entire pre-allocated buffer, initialized
        to 0x00 where not overwritten.
        In non-strict mode, return only written bytes.
        """
        if self.strict:
            return bytes(self.bfr)
        else:
            return bytes(self.bfr[:self.length])


