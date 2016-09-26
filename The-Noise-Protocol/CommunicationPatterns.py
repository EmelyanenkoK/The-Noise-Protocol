# This file contains the different handshake patterns
# Following the naming conventions shown on the website as of (9/23/16)
# https://noiseprotocol.org/noise.html#handshake-patterns


# naming clarification:
# HSPattern = Hand Shake Pattern
# Pattern = Container for the patterns.

# imports
from collections import namedtuple

# Main identification container.
HSPattern = namedtuple('HSPattern', ('pre_reqs', 'pre', 'post', 'messagePatterns'))

# Adding one way patterns.
Patterns = {

    #   One-way patterns
    #   Naming convention for one-way patterns:
    #   N = no static key for sender
    #   K = static key for sender known to recipient
    #   X = static key for sender transmitted to recipient
    #   Noise_N(rs):
    #       <- s
    #       ...
    #       -> e, dhes
    #
    #   Noise_K(s, rs):
    #       -> s
    #       <- s
    #       ...
    #       -> e, dhes, dhss
    #
    #   Noise_X(s, rs):
    #       <- s
    #       ...
    #       -> e, dhes, s, dhss

    'NOISE_N': HSPattern(('rs',), '', 's', (('e', 'dhes'),)),
    'NOISE_K': HSPattern(('s', 'rs'), 's', 's', (('e', 'dhes', 'dhss'),)),
    'NOISE_X': HSPattern(('s', 'rs'), '', 's', (('e', 'dhes', 's', 'dhss'),)),

    #     Naming convention
    #
    # N_ = no static key for initiator
    # K_ = static key for initiator known to responder
    # X_ = static key for initiator transmitted to responder
    # I_ = static key for initiator immediately transmitted to responder,
    #      despite reduced or absent identity-hiding
    #
    # _N = no static key for responder
    # _K = static key for responder known to initiator
    # _X = static key for responder transmitted to initiator
    #
    #
    # Noise_NN():                      Noise_KN(s):
    # -> e                             -> s
    # < - e, dhee                      ...
    #                                  -> e
    #                                  < - e, dhee, dhes
    #
    # Noise_NK(rs):                    Noise_KK(s, rs):
    # < - s                            -> s
    #  ...                             < - s
    # -> e, dhes                       ...
    # < - e, dhee                      -> e, dhes, dhss
    #                                  < - e, dhee, dhes
    #
    # Noise_NX(rs):                    Noise_KX(s, rs):
    # -> e                             -> s
    # < - e, dhee, s, dhse             ...
    #                                  -> e
    #                                  <- e, dhee, dhes, s, dhse
    #
    # Noise_XN(s):                     Noise_IN(s):
    # -> e                             -> e, s
    # < - e, dhee                      < - e, dhee, dhes
    # -> s, dhse

    # Noise_XK(s, rs):                 Noise_IK(s, rs):
    # < - s                            < - s
    #  ...                             ...
    # -> e, dhes                       -> e, dhes, s, dhss
    # <- e, dhee                       <- e, dhee, dhes
    # -> s, dhse
    #
    # Noise_XX(s, rs):                 Noise_IX(s, rs):
    # -> e                             -> e, s
    # < - e, dhee, s, dhse             < - e, dhee, dhes, s, dhse
    # -> s, dhse

    # Noise_N implementation - No static key for responder
    'Noise_NN': HSPattern((), '', '', (('e',), ('e', 'dhee'),)),
    'Noise_KN': HSPattern(('s',), 's', '', (('e',), ('e', 'dhee', 'dhes'),)),
    'Noise_XN': HSPattern(('s',), '', '', (('e',), ('e', 'dhee'), ('s', 'dhse'),)),
    'Noise_IN': HSPattern(('s',), '', '', (('e', 's'), ('e', 'dhee', 'dhes'),)),

    # Noise_*K - Known static key for responder
    'Noise_NK': HSPattern(('rs',), '', 's', (('e', 'dhes'), ('e', 'dhee'),)),
    'Noise_KK': HSPattern(('s', 'rs'), 's', 's', (('e', 'dhes', 'dhss'), ('e', 'dhes', 'dhss'),)),
    'Noise_XK': HSPattern(('s', 'rs'), '', 's', (('e', 'dhes'), ('e', 'dhee'), ('s', 'dhse'),)),
    'Noise_IK': HSPattern(('s', 'rs'), '', 's', (('e', 'dhes', 's', 'dhss'), ('e', 'dhee', 'dhes'),)),

    # Noise_*X - Static key transmitted by responder
    'Noise_NX': HSPattern(('rs',), '', '', (('e',), ('e', 'dhee', 's', 'dhse'),)),
    'Noise_KX': HSPattern(('s', 'rs'), 's', '', (('e',), ('e', 'dhee', 'dhes', 's', 'dhse'),)),
    'Noise_XX': HSPattern(('s', 'rs'), '', '', (('e',), ('e', 'dhee', 's', 'dhse'), ('s', 'dhse'),)),
    'Noise_IX': HSPattern(('s', 'rs'), '', '', (('e', 's'), ('e', 'dhee', 'dhes', 's', 'dhse'),))

}
