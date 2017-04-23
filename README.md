# The-Noise-Protocol
This repository is the implementation of Transport level of Lightning Networks, [BOLT-08](https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md)

# TODO
1. Add examples
2. Raise informative exceptions
3. Handle session breaks

# Installation
`apk add tlslite-ng` 

Build [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1) with ecdh (flag `--enable-module-ecdh` for `./configure`)
 
