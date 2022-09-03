#
#   07 - AES in ECB mode
#

from Crypto.Cipher import AES
from helper_c07 import load_data

def pkcs7_unpadding(input: bytes) -> bytes:
    last_byte = input[-1]
    if input[-last_byte:] == last_byte * last_byte.to_bytes(1, "big"):
        return input[:-last_byte]
    else:
        return input

def decrypt_aes_ecb(input: bytes, key: bytes) -> bytes:
    blocks = list((input[i * 16 : i * 16 + 16]) for i in range(16))
    
    decrypted = b""
    for block in blocks:
        cipher_block = AES.new(key, AES.MODE_ECB)
        decrypted += cipher_block.decrypt(block)

    return pkcs7_unpadding(decrypted)

def c07(file_name, key):
    return decrypt_aes_ecb(load_data(file_name), key)