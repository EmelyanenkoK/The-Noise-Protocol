# This file contains the different handshake patterns
# Following the naming conventions shown on the website as of (9/23/16)
# https://noiseprotocol.org/noise.html#handshake-patterns


# naming clarification:
# HSPattern = Hand Shake Pattern
# Pattern = Container for the patterns.

# imports
from collections import namedtuple

# Main identification container.
HSPattern = namedtuple('HandshakePattern', ('pre_reqs', 'pre', 'post', 'messagePatterns'))

# Adding one way patterns.
Patterns = {
    # One-way patterns
    'NOISE_N': HSPattern(('rs',), '', 's', (('e', 'dhes'),)),
    'NOISE_K': HSPattern(('s', 'rs'), 's', 's', (('e', 'dhes', 'dhss'),)),
    'NOISE_X': HSPattern(('s', 'rs'), '', 's', (('e', 'dhes', 's', 'dhss'),)),
}
