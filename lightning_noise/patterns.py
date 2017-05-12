from collections import namedtuple

HandshakePattern = namedtuple('HandshakePattern', ('prereq', 'i_pre', 'r_pre', 'message_patterns'))

HSPatterns = {
    # One-way patterns
    b'Noise_N': HandshakePattern(('rs',), '', 's',(('e', 'dhes'),)),
    b'Noise_K': HandshakePattern(('s', 'rs'), 's', 's',(('e', 'dhes', 'dhss'),)),
    b'Noise_X': HandshakePattern(('s', 'rs'), '', 's',(('e', 'dhes', 's', 'dhss'),)),

    # Noise_*N - No static key for responder
    b'Noise_NN': HandshakePattern((), '', '', (('e',), ('e', 'dhee'),)),
    b'Noise_KN': HandshakePattern(('s',), 's', '', (('e',), ('e', 'dhee', 'dhes'),)),
    b'Noise_XN': HandshakePattern(('s',), '', '',(('e',),('e', 'dhee'), ('s', 'dhse'),)),
    b'Noise_IN': HandshakePattern(('s',), '', '',(('e', 's'),('e', 'dhee', 'dhes'),)),

    # Noise_*K - Known static key for responder
    b'Noise_NK': HandshakePattern(('rs',), '', 's',(('e', 'dhes'),('e', 'dhee'),)),
    b'Noise_KK': HandshakePattern(('s', 'rs'), 's', 's',(('e', 'dhes', 'dhss'),('e', 'dhes', 'dhss'),)),
    b'Noise_XK': HandshakePattern(('s', 'rs'), 's', 's',(('e', 'dhes'),('e', 'dhee'),('s', 'dhse'),)),
    'Noise_IK': HandshakePattern(('s', 'rs'), '', 's',(('e', 'dhes', 's', 'dhss'),('e', 'dhee', 'dhes'),)),

    # Noise_*X - Static key transmitted by responder
    b'Noise_NX': HandshakePattern(('rs',), '', '',(('e',),('e', 'dhee', 's', 'dhse'),)),
    b'Noise_KX': HandshakePattern(('s', 'rs'), 's', '',(('e',),('e', 'dhee', 'dhes', 's', 'dhse'),)),
    b'Noise_XX': HandshakePattern(('s', 'rs'), '', '',(('e',),('e', 'dhee', 's', 'dhse'),('s', 'dhse'),)),
    b'Noise_IX': HandshakePattern(('s', 'rs'), '', '',(('e', 's'),('e', 'dhee', 'dhes', 's', 'dhse'),))
}
