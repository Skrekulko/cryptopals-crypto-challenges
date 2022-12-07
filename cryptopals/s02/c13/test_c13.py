#
#   13 - ECB cut-and-paste
#

from cryptopals.s02.c13.solution_c13 import MyOracle, Decipher

def test_c13() -> None:
    # Oracle
    oracle = MyOracle()

    # Part Of Postfix To Hijack
    role = b"user"

    # Hijacked Cipher
    hijacked = Decipher.aes_ecb_hijack(oracle, b"admin", len(role))

    assert b"admin" in oracle.decrypt(hijacked)
