#
#   26 - CTR bitflipping
#

from cryptopals.s04.c26.solution_c26 import MyOracle, Decipher


def test_c26():
    # Oracle
    oracle = MyOracle()

    # Plaintext To Inject
    plaintext = b";admin=true"

    # Get The Modified Ciphertext
    modified_ciphertext = Decipher.aes_ctr_injection(oracle, plaintext)

    assert oracle.is_admin(oracle.decrypt(modified_ciphertext))
