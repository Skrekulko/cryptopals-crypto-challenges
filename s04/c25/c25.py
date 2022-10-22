#
#   25 - Break "random access read/write" AES CTR
#

from helper_c25 import fixed_xor, AES128CTR

def edit(ciphertext: bytes, key: bytes, nonce: int, offset: int, newtext: bytes) -> bytes:
    # Decrypt The Ciphertext
    plaintext = AES128CTR.transform(ciphertext, key, nonce)
    
    # Replace The Original Plaintext With A New Plaintext
    new_plaintext = plaintext[:offset] + newtext + plaintext[offset + len(newtext):]
    
    # Encrypt The New Plaintext
    new_ciphertext = AES128CTR.transform(new_plaintext, key, nonce)
    
    return new_ciphertext

def c25(ciphertext: bytes, key: bytes, nonce: int):
    # Craft A New Plaintext
    crafted_plaintext = b"A" * len(ciphertext)
    
    # Edit The Ciphertext
    new_ciphertext = edit(ciphertext, key, nonce, 0, crafted_plaintext)
    
    # XOR Known Plaintext With New Ciphertext
    xored = fixed_xor(new_ciphertext, crafted_plaintext)
    
    # Recover Original Plaintext
    recovered_plaintext = fixed_xor(ciphertext, xored)

    return recovered_plaintext