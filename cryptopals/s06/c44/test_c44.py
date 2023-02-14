#
#   44 - DSA nonce recovery from repeated nonce
#

from cryptopals.asymmetric import DSA
from cryptopals.hash import SHA1
from cryptopals.utils import Math
from random import randint


def test_c44() -> None:
    # DSA Oracle
    dsa = DSA()

    # Messages
    message1 = b"First message."
    message2 = b"Second message."

    # Broken DSA Implementation Uses The Same 'k' Everytime
    k = randint(1, dsa.parameters.q - 1)

    # Known First And Second Signing Component
    (r1, s1) = dsa.sign(message=message1, k=k)
    (r2, s2) = dsa.sign(message=message2, k=k)

    # The Leftmost min(N, outlen) Bits Of Hash(M)
    digest1 = int.from_bytes(SHA1.digest(m=message1), "big")
    digest_len1 = digest1.bit_length()
    z1 = digest1 >> (digest_len1 - Math.gcd(dsa.parameters.q.bit_length(), digest_len1))

    digest2 = int.from_bytes(SHA1.digest(m=message2), "big")
    digest_len2 = digest2.bit_length()
    z2 = digest2 >> (digest_len2 - Math.gcd(dsa.parameters.q.bit_length(), digest_len2))

    # Modular Inverse Of The First And Second Signing Component 'r' And 's'
    r2_inv = Math.mod_inv(a=r2, m=dsa.parameters.q)
    s1_inv = Math.mod_inv(a=s1, m=dsa.parameters.q)

    # Calculate The Subkey 'k'
    numerator = s1_inv * (z1 - z2 * r2_inv * r1) % dsa.parameters.q
    denominator = (1 - s1_inv * s2 * r2_inv * r1) % dsa.parameters.q
    k = numerator * Math.mod_inv(a=denominator, m=dsa.parameters.q) % dsa.parameters.q

    # Calculate The Private Key 'x'
    x = (s2 * k - z2) * r2_inv % dsa.parameters.q

    assert  x == dsa.parameters.x
