#
#   14 - Byte-at-a-time ECB decryption (Harder)
#

from cryptopals.s02.c14.solution_c14 import MyOracle, Decipher


def test_c14() -> None:
    # Oracle
    oracle = MyOracle()

    # Valid Result
    result = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll" \
             b"cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    
    assert Decipher.aes_ecb_postfix_random_prefix(oracle) == result
