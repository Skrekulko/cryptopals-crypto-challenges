#
#   12 - Byte-at-a-time ECB decryption (Simple)
#

from cryptopals.s02.c12.solution_c12 import MyOracle, Decipher


def test_c12() -> None:
    # Oracle
    oracle = MyOracle()

    # Valid Result
    result =\
        b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll" \
        b"cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    
    assert Decipher.aes_ecb_postfix(oracle) == result
