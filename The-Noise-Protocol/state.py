from patterns import HSPatterns
from NoiseTypes import empty
from errors import HandshakeError

import logging
logger = logging.getLogger(__name__)

import os
class CipherState(object):
    def __init__(self, cipher, key=empty):
        self.cipher = cipher
        self.initialize_key(key)

    def initialize_key(self, key):
        self.k = key
        self.n = 0#int.from_bytes(os.urandom(8),'big')

    @property
    def has_key(self):
        return self.k is not empty

    def encrypt_with_ad(self, ad, plaintext):
        if self.k is empty:
            return plaintext
        ret = self.cipher.encrypt(self.k, self.n.to_bytes(8,'big'), ad, plaintext)
        self.n += 1
        return ret

    def decrypt_with_ad(self, ad, ciphertext):
        if self.k is empty:
            return ciphertext
        ret = self.cipher.decrypt(self.k, self.n, ad, ciphertext)
        self.n += 1
        return ret


class SymmetricState(object):
    def __init__(self, dh, cipher, hasher, protocol_name=None):
        self.dh = dh
        self.hasher = hasher
        self.cipherstate = CipherState(cipher)
        if protocol_name is not None:
            self.initialize_symmetric(protocol_name)

    def initialize_symmetric(self, protocol_name):
        diff = self.hasher.HASHLEN - len(protocol_name)
        if diff >= 0:
            self.h = protocol_name + bytes(diff)
        else:
            self.h = self.hasher.hash(protocol_name)
        self.ck = self.h
        self.cipherstate.initialize_key(empty)
        logger.debug("Handshake hash init: %s"%hex(int.from_bytes(self.h, 'big')))
        logger.debug("Chaining key init: %s"%hex(int.from_bytes(self.ck, 'big')))

    def mix_key(self, input_key_material):
        self.ck, temp_k = self.hasher.hkdf(self.ck, input_key_material,
                                           dh=self.dh)
        self.cipherstate.initialize_key(temp_k)
        logger.debug("Chaining key update: %s"%hex(int.from_bytes(self.ck, 'big')))
        

    def mix_hash(self, data):
        self.h = self.hasher.hash(self.h + data)
        logger.debug("Handshake hash update: %s"%hex(int.from_bytes(self.h, 'big')))

    def encrypt_and_hash(self, plaintext):
        ciphertext = self.cipherstate.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext):
        plaintext = self.cipherstate.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self):
        temp_k1, temp_k2 = self.hasher.hkdf(self.ck, b'')
        if self.hasher.HASHLEN == 64:
            temp_k1, temp_k2 = temp_k1[:32], temp_k2[:32]
        c1 = CipherState(self.cipherstate.cipher, temp_k1)
        c2 = CipherState(self.cipherstate.cipher, temp_k2)
        return c1, c2


class HandshakeState(object):
    def __init__(self, dh, cipher, hasher):
        self.dh = dh
        self.cipher = cipher
        self.hasher = hasher

    def initialize(self, handshake_pattern, prologue=b'',
                   s=empty, e=empty, rs=empty, re=empty):
        protocol_name = b'_'.join((handshake_pattern, self.dh.NAME,
                                   self.cipher.NAME, self.hasher.NAME))
        logger.debug("Protocol name is composed: %s"%protocol_name)
        self.symmetricstate = SymmetricState(self.dh, self.cipher, self.hasher,
                                             protocol_name)
        self.symmetricstate.mix_hash(prologue)
        self.s = s
        self.e = e
        self.rs = rs
        self.re = re

        pattern = HSPatterns[handshake_pattern]
        if pattern.i_pre not in ('', 's', 'e', 'se'):
            raise HandshakeError("Invalid initiator pre-message")
        if pattern.r_pre not in ('', 's', 'e', 'se'):
            raise HandshakeError("Invalid responder pre-message")
        for token in pattern.i_pre:
            if token == 's':
                if self.s is empty:
                    raise HandshakeError("No static public key (initiator)")
                self.symmetricstate.mix_hash(self.s.public())
            elif token == 'e':
                if self.e is empty:
                    raise HandshakeError("No ephemeral public key (initiator)")
                self.symmetricstate.mix_hash(self.e.public())
        for token in pattern.r_pre:
            if token == 's':
                if self.rs is empty:
                    raise HandshakeError("No static public key (responder)")
                self.symmetricstate.mix_hash(self.rs.serialize())
            elif token == 'e':
                if self.re is empty:
                    raise HandshakeError("No ephemeral public key (responder)")
                self.symmetricstate.mix_hash(self.re.serialize())

        self.message_patterns = list(pattern.message_patterns)

    def write_message(self, payload, message_buffer):
        message_pattern = self.message_patterns.pop(0)
        for token in message_pattern:
            if token == 'e':
                self.e = self.dh.generate_keypair()
                message_buffer.append(self.e.public_key())
                self.symmetricstate.mix_hash(self.e.public_key())
            elif token == 's':
                msg = self.symmetricstate.encrypt_and_hash(self.s.public_key())
                message_buffer.append(msg)
            elif token[:2] == 'dh':
                try:
                    x = {'e': self.e, 's': self.s}[token[2]]
                    y = {'e': self.re, 's': self.rs}[token[3]]
                except KeyError:
                    raise HandshakeError("Invalid pattern: " + token)
                self.symmetricstate.mix_key(self.dh.DH(x, y))
            else:
                raise HandshakeError("Invalid pattern: " + token)
        message_buffer.append(self.symmetricstate.encrypt_and_hash(payload))
        
        if len(self.message_patterns) == 0:
            return self.symmetricstate.split()

    def read_message(self, message, payload_buffer):
        message_pattern = self.message_patterns.pop(0)
        for token in message_pattern:
            if token == 'e':
                if len(message) < self.dh.DHLEN:
                    raise HandshakeError("Message too short""")
                self.re = message[:self.dh.DHLEN]
                message = message[self.dh.DHLEN:]
                self.symmetricstate.mix_hash(self.re.serialize())
            elif token == 's':
                has_key = self.symmetricstate.cipherstate.has_key
                nbytes = self.dh.DHLEN + 16 if has_key else self.dh.DHLEN
                if len(message) < nbytes:
                    raise HandshakeError("Message too short""")
                temp, message = message[:nbytes], message[nbytes:]
                if has_key:
                    self.rs = self.symmetricstate.decrypt_and_hash(temp)
                else:
                    self.rs = temp
            elif token[:2] == 'dh':
                try:
                    x = {'e': self.e, 's': self.s}[token[2]]
                    y = {'e': self.re, 's': self.rs}[token[3]]
                except KeyError:
                    raise HandshakeError("Invalid pattern: " + token)
                self.symmetricstate.mix_key(self.dh.DH(x, y))
            else:
                raise HandshakeError("Invalid pattern: " + token)
        payload_buffer.append(self.symmetricstate.decrypt_and_hash(message))

        if len(self.message_patterns) == 0:
            return self.symmetricstate.split()


