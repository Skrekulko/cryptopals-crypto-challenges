#
#   39 - Implement RSA
#

from cryptopals.s05.c39.solution_c39 import RSA


def test_c39() -> None:
    # Key Size In Bits
    key_size = 1024
    
    # Public Exponent 'e'
    e = 3
    
    # Message
    message = int.from_bytes(b"Hello!", "big")
    
    # RSA
    rsa = RSA(bits=key_size, e=e)

    # Encrypted Message
    encrypted = rsa.encrypt(message=message)

    # Decrypt The Message And Compare With Plaintext
    assert rsa.decrypt(message=encrypted) == message
