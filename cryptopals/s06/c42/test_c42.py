#
#   42 - Bleichenbacher's e=3 RSA Attack
#

from cryptopals.s06.c42.solution_c42 import MyOracle, bleichenbacher_signature


def test_c42() -> None:
    # RSA Oracle
    oracle = MyOracle()

    # Plaintext
    plaintext = b"\x00\x00\x2e\x36"

    # Forged Signature
    forged_signature = bleichenbacher_signature(n_size=oracle.key_length, e=oracle.e, data=plaintext)

    assert oracle.verify(signature=forged_signature, data=plaintext)