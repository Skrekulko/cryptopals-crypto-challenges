#
#   39 - Implement RSA
#

from cryptopals.s05.c39.solution_c39 import RSA


def test_c39() -> None:
    # Key Size In Bits
    key_size = 1024
    
    # Public Exponent 'e'
    e = 3
    
    # Plaintext
    plaintext = b"Hello!"
    
    # RSA
    rsa = RSA(key_size, e)

    assert rsa.decrypt(RSA(key_size, e).encrypt(plaintext)) == plaintext
