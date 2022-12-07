#
#   41 - Implement unpadded message recovery oracle
#

from cryptopals.s06.c41.solution_c41 import MyOracle
from cryptopals.utils import Converter, Generator, Math


def test_c41() -> None:
    # Oracle
    oracle = MyOracle()

    # Public Exponent 'e'
    e = oracle.rsa.e

    # Public Modulus 'n'
    n = oracle.rsa.n

    # Captured Ciphertext (Integer)
    ciphertext = int.from_bytes(oracle.ciphertext, "big")

    # Random Number
    while True:
        s = Generator.random_int()

        # 's > 1 mod n'
        if s % n > 1:
            break

    # Crafted Ciphertext (Bytes)
    crafted_ciphertext = Converter.int_to_hex(
        (Math.mod_pow(s, e, n) * ciphertext) % n
    )

    # Submit The Crafted Ciphertext And Get The Crafted Plaintext
    crafted_plaintext = int.from_bytes(
        oracle.decrypt(ciphertext=crafted_ciphertext), "big"
    )

    # Calculate The Original Plaintext
    plaintext = Converter.int_to_hex(
        (crafted_plaintext * Math.mod_inv(a=s, m=n)) % n
    )

    assert plaintext == oracle.plaintext
