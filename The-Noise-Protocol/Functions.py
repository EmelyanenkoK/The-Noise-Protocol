from collections import namedtuple
import libnacl
from helpers import *

from libnacl import \
    crypto_box_keypair as x25519_keypair, \
    crypto_box_beforenm as x25519_dh, \
    crypto_hash_sha256 as sha256_hash, \
    crypto_hash_sha512 as sha512_hash, \
    crypto_generichash as blake2b_hash

from pysodium import \
    crypto_aead_chacha20poly1305_decrypt as chachapoly_decrypt, \
    crypto_aead_chacha20poly1305_encrypt as chachapoly_encrypt


class Singleton:

    __instance = None

    def __new__(self, *args, **kwargs):
        """Return instance of class, creating if necessary"""
        if self.__instance is None:
            self.__instance = object.__new__(self, *args, **kwargs)
        return self.__instance

    def __call__(self):
        raise TypeError('This must will be called only on new.')


class Hash(Singleton):
    hash_length = None
    block_length = None

    def hmac_hash(self, key, data):
        if len(key) < self.block_length:
            key = key.rjust(self.block_length, b'\x00')
        else:
            key = self.HASH(key)

        opad = bytes(0x5c ^ byte for byte in key)
        ipad = bytes(0x36 ^ byte for byte in key)
        return self.HASH(opad + self.HASH(ipad + data))


class BLAKE2b(Hash):
    HASHLEN = 64
    BLOCKLEN = 128
    NAME = b'BLAKE2b'
    hash = blake2b_hash

class BLAKE2s(Hash):
    hash_length = 32
    block_length = 64
    NAME = b'BLAKE2s'

class SHA256(Hash):
    hash_length = 32
    block_length = 64
    NAME = b'SHA256'
    hash = sha256_hash


class SHA512(Hash):
    hash_length = 64
    block_length = 128
    NAME = b'SHA512'
    hash = sha512_hash



