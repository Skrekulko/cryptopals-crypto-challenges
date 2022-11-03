#
#   40 - Implement an E=3 RSA Broadcast attack
#

from c40 import RSA, c40

def test_c40() -> None:
    # Key Length In Bits
    key_length = 1024
    
    # Plaintext
    plaintext = b"Hello!"
    
    # Public Exponents 'e'
    e = 3
    
    # For Different Public Exponents Up To 'e'
    rsa_ciphertexts = []
    rsa_n = []
    for _ in range(e):
        # RSA
        rsa = RSA(key_length, e)
        
        # Append Ciphertext
        rsa_ciphertexts.append(rsa.encrypt(plaintext))
        
        # Append Public Modulus 'n'
        rsa_n.append(rsa.n)

    assert c40(rsa_ciphertexts, rsa_n, e) == plaintext
