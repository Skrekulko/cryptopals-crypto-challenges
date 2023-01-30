#
#   42 - Bleichenbacher's e=3 RSA Attack
#

from cryptopals.s06.c42.solution_c42 import MyOracle, bleichenbacher_signature


def test_c42() -> None:
    # RSA Oracle
    oracle = MyOracle()

    # Plaintext
    plaintext = b"hi mom"

    # Forged Signature
    forged_signature = bleichenbacher_signature(key_size=oracle.key_length, data=plaintext)

    assert oracle.verify(signature=forged_signature, data=plaintext)