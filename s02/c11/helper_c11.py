#
#   02 - Fixed XOR
#

def fixed_xor(input1: bytes, input2: bytes) -> bytes:
    if len(input1) == len(input2):
        return bytes(a ^ b for (a, b) in zip(input1, input2))
    else:
        raise ValueError

#
#   09 - Implement PKCS#7 padding
#

def pkcs7_padding(input: bytes, block_size: int) -> bytes:
    len_input = len(input)
    len_padding = block_size - (len_input % block_size)
    
    if len_padding == block_size:
        return input
    
    padding = len_padding * len_padding.to_bytes(1, "big")
    
    padded_input = input + padding
    
    return padded_input

#
#   10 - Implement CBC mode
#

from Crypto.Cipher import AES

def encrypt_aes_ecb_block(block: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(block)
