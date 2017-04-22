# The-Noise-Protocol
This repository is the implementation of Transport level of Lightning Networks, [BOLT-08](https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md)
# Issues
This implementation uses 4 different cryptolibraries + standard library for hmac:
1. libsecp256k1 for Diffie-Hellman and Private/Public keys handling
2. libsodium
3. tlslite for chacha20_poly1305, since libsodium uses 64bit nonce, but BOLT-8 requires 96bit
4. libnacl for sha256

# TODO
1. Shrink dependencies
2. Add examples
3. Raise informative exceptions
4. Handle session breaks

# Installation
`apk add libsodium pysodium tlslite-ng libnacl pynacl` 

 Build [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1) with ecdh (flag `--enable-module-ecdh` for `./configure`)
 
