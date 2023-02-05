#
#   41 - Implement unpadded message recovery oracle
#

from cryptopals.s06.c41.solution_c41 import Oracle
from cryptopals.utils import Generator, Math


def test_c41() -> None:
    # Oracle
    oracle = Oracle()

    # Public Exponent 'e'
    e = oracle.parameters.e

    # Public Modulus 'n'
    n = oracle.parameters.n

    # Captured Ciphertext
    ciphertext = oracle.ciphertext

    # Random Number
    while True:
        s = Generator.random_int()

        # 's > 1 mod n'
        if s % n > 1:
            break

    # Crafted Ciphertext (Bytes)
    crafted_ciphertext = (Math.mod_pow(s, e, n) * ciphertext) % n

    # Submit The Crafted Ciphertext And Get The Crafted Plaintext
    crafted_plaintext = oracle.decrypt(message=crafted_ciphertext)

    # Calculate The Original Plaintext
    plaintext = crafted_plaintext * Math.mod_inv(a=s, m=n) % n

    assert plaintext == oracle.plaintext
