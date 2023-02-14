#
#   43 - DSA key recovery from nonce
#

from cryptopals.s06.c43.solution_c43 import DSA
from cryptopals.hash import SHA1
from cryptopals.utils import Math
from random import randint


def test_c43() -> None:
    # DSA Oracle
    dsa = DSA()

    # Message
    message = b"For those that envy a MC it can be hazardous to your health \n" \
              b"So be friendly, a matter of life and death, just like a etch-a-sketch"

    # Broken DSA Implementation That Generates Small 'k'
    k = randint(1, 2 ** 16)

    # Known First And Second Signing Component
    # r = 548099063082341131477253921760299949438196259240
    # s = 857042759984254168557880549501802188789837994940
    (r, s) = dsa.sign(message=message, k=k)

    # The Leftmost min(N, outlen) Bits Of Hash(M)
    digest = int.from_bytes(SHA1.digest(m=message), "big")
    digest_len = digest.bit_length()
    z = digest >> (digest_len - Math.gcd(dsa.parameters.q.bit_length(), digest_len))

    # Modular Inverse Of The First Signing Component 'r'
    r_inv = Math.mod_inv(a=r, m=dsa.parameters.q)

    # Try For Every Possible 'k'
    for k in range(1, 2 ** 16):
        # Compute The Private Key 'x'
        x = (s * k - z) * r_inv % dsa.parameters.q

        # Sign The Message With The Computed Private Key 'x'
        (r2, s2) = dsa.sign(message=message, x=x, k=k)

        # Match Found
        if (r, s) == (r2, s2):
            assert x == dsa.parameters.x
            break

    raise Exception("Private key not found.")
