from NoiseTypes import SHA256, ChaChaPoly
from dh_secp256k1 import DiffieHellmanSecp256k1, Key
import state

def HandshakeState():
    return state.HandshakeState(DiffieHellmanSecp256k1(), ChaChaPoly, SHA256)


