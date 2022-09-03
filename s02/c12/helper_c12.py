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

from Crypto.Cipher import AES
from collections import Counter
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
    
def detect_aes_ecb_or_cbc(cipher: bytes) -> tuple[str, bytes]:
    cipher_len = len(cipher)
    n_blocks = cipher_len // 16
    chunks = Counter((cipher[i * 16 : i * 16 + 16]) for i in range(n_blocks))
    
    return ("ecb", max(chunks)) if len(chunks) != n_blocks else ("cbc", list(chunks.elements())[0])
