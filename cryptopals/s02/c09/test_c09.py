#
#   09 - Implement PKCS#7 padding
#

from cryptopals.s02.c09.solution_c09 import PKCS7


def test_c09() -> None:
    # Plaintext
    plaintext = b"YELLOW SUBMARINE"

    # AES Block Size
    BLOCK_SIZE = 20

    # Valid Result
    result = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    
    assert PKCS7.padding(plaintext, BLOCK_SIZE) == result
