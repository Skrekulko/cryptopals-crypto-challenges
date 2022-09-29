#
#   20 - Break fixed-nonce CTR statistically
#

from helper_c20 import repeating_key_xor, single_byte_xor_decipher

# Break AES CTR Mode
def break_aes_ctr(ciphertexts: list, key: bytes, nonce: int) -> list[bytes]:
    # Construct The Keystream
    keystream = b""
    for i in range(max(map(len, ciphertexts))):
        # Construct A Column Of nth Ciphertext Characters
        column = b""
        for ciphertext in ciphertexts:
            column += ciphertext[i].to_bytes(1, "little") if i < len(ciphertext) else b""
            
        # Break The Single Byte Using Frequency Analysis
        keystream += single_byte_xor_decipher(column)[1].to_bytes(1, "little")
    
    # Decrypt The Ciphertexts
    plaintexts = []
    for ciphertext in ciphertexts:
        plaintexts.append(repeating_key_xor(ciphertext, keystream))
    
    return plaintexts

def c20(ciphertexts: list, key: bytes, nonce: int) -> list[bytes]:
    return break_aes_ctr(ciphertexts, key, nonce)