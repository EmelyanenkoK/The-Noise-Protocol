from .NoiseTypes import SHA256, ChaChaPoly
from .dh_secp256k1 import DiffieHellmanSecp256k1, Key
from .state import HandshakeState as HS

def HandshakeState():
    return HS(DiffieHellmanSecp256k1(), ChaChaPoly, SHA256)


