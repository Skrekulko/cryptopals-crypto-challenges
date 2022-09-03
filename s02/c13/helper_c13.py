#
#   07 - AES in ECB mode
#

from Crypto.Cipher import AES

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
#   11 - An ECB/CBC detection oracle
#

from random import randint
from os import urandom

class Generator:
    @staticmethod
    def generate_random_bytes(min = 1, max = 16) -> bytes:
        return urandom(randint(min, max))
        
    @staticmethod
    def generate_key_128b() -> bytes:
        return urandom(16)
        
def encrypt_aes_ecb(input: bytes, key: bytes) -> bytes:
    padded_input = pkcs7_padding(input, 16)
    n_blocks = int(len(padded_input) / 16)
    blocks = list((padded_input[i * 16 : i * 16 + 16]) for i in range(n_blocks))
    
    encrypted = b""
    for block in blocks:
        cipher_block = AES.new(key, AES.MODE_ECB)
        encrypted += cipher_block.encrypt(block)

    return encrypted
