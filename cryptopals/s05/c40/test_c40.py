#
#   40 - Implement an E=3 RSA Broadcast attack
#

from cryptopals.s05.c40.solution_c40 import rsa_broadcast_attack
from cryptopals.asymmetric import RSA


def test_c40() -> None:
    # Key Size In Bits
    key_size = 1024
    
    # Message
    message = int.from_bytes(b"Hello!", "big")
    
    # Public Exponents 'e'
    e = 3
    
    # For Different Public Exponents Up To 'e'
    rsa_ciphertexts = []
    rsa_n = []
    for _ in range(e):
        # RSA
        rsa = RSA(bits=key_size, e=e)
        
        # Append Ciphertext
        rsa_ciphertexts.append(rsa.encrypt(message=message))
        
        # Append Public Modulus 'n'
        rsa_n.append(rsa.parameters.n)

    assert rsa_broadcast_attack(rsa_ciphertexts, rsa_n, e) == message
