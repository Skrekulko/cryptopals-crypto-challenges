#
#   45 - DSA parameter tampering
#

from cryptopals.s06.c45.solution_c45 import DSA
from cryptopals.utils import Math


def test_c45() -> None:
    # DSA Oracle
    dsa = DSA(bypass=True)

    # Corrupt The Generator 'g'
    dsa.parameters.g = 0
    dsa.parameters.y = Math.mod_pow(b=dsa.parameters.g, e=dsa.parameters.x, m=dsa.parameters.p)

    # Messages
    message1 = b"Hello, world"
    message2 = b"Goodbye, world"

    # Signatures
    (r1, s1) = dsa.sign(message=message1)
    (r2, s2) = dsa.sign(message=message2)

    # Verify The Signatures With Their Corresponding Messages
    assert dsa.verify(message=message1, r=r1, s=s1) and dsa.verify(message=message1, r=r2, s=s2)

    # Verify The Signatures With Different Messages
    assert dsa.verify(message=message2, r=r1, s=s1) and dsa.verify(message=message2, r=r2, s=s2)

    # Corrupt The Generator 'g'
    dsa.parameters.g = dsa.parameters.p + 1
    dsa.parameters.y = Math.mod_pow(b=dsa.parameters.g, e=dsa.parameters.x, m=dsa.parameters.p)

    # Signatures
    (r1, s1) = dsa.sign(message=message1)
    (r2, s2) = dsa.sign(message=message2)

    # Verify The Signatures With Their Corresponding Messages
    assert dsa.verify(message=message1, r=r1, s=s1) and dsa.verify(message=message1, r=r2, s=s2)
