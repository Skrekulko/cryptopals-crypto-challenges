#
#   16 - CBC bitflipping attacks
#

from cryptopals.s02.c16.solution_c16 import MyOracle, Decipher


def test_c16() -> None:
    # Oracle
    oracle = MyOracle()

    # Plaintext To Inject
    plaintext = b";admin=true;"

    # Get Ciphertext With Injected Plaintext
    ciphertext = Decipher.aes_cbc_injection(oracle, plaintext)

    assert oracle.decrypt_and_check_admin(ciphertext)
