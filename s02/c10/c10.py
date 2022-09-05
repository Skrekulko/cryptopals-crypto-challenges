#
#   10 - Implement CBC mode
#

from Crypto.Cipher import AES
from helper_c10 import fixed_xor, pkcs7_unpadding, load_data

def encrypt_aes_ecb_block(block: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(block)

def decrypt_aes_ecb_block(block: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(block)

def decrypt_aes_cbc(input: bytes, key: bytes, iv: bytes) -> bytes:
    n_blocks = int(len(input) / 16)
    in_blocks = list((input[i * 16 : i * 16 + 16]) for i in range(n_blocks)) 
    
    decrypted = fixed_xor(decrypt_aes_ecb_block(in_blocks[0], key), iv)
    
    for i in range(1, n_blocks):
       decrypted += fixed_xor(decrypt_aes_ecb_block(in_blocks[i], key), in_blocks[i - 1])
        
    return pkcs7_unpadding(decrypted)

def c10(file_name, key, iv):
    return decrypt_aes_cbc(load_data(file_name), key, iv)