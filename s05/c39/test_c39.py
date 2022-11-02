#
#   39 - Implement RSA
#

from c39 import RSA, c39

def test_c39() -> None:
    # Key Length In Bits
    key_length = 1024
    
    # Public Exponent 'e'
    e = 3
    
    # Plaintext
    plaintext = b"Hello!"
    
    # RSA
    rsa = RSA(key_length)

    assert rsa.decrypt(
        c39(key_length, e, plaintext)
    ) == plaintext
