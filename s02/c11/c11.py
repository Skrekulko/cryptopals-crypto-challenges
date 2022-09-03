#
#   11 - An ECB/CBC detection oracle
#

from Crypto.Cipher import AES
from collections import Counter
from random import randint
from os import urandom
from helper_c11 import fixed_xor, pkcs7_padding, encrypt_aes_ecb_block

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

def encrypt_aes_cbc(input: bytes, key: bytes, iv: bytes) -> bytes:
    padded_input = pkcs7_padding(input, 16)
    n_blocks = int(len(padded_input) / 16)
    in_blocks = list((padded_input[i * 16 : i * 16 + 16]) for i in range(n_blocks)) 
    
    encrypted = encrypt_aes_ecb_block(fixed_xor(in_blocks[0], iv), key)
    for i in range(1, n_blocks):
       encrypted += encrypt_aes_ecb_block(fixed_xor(in_blocks[i], in_blocks[i - 1]), key)
        
    return encrypted

def encrypt_oracle(input: bytes) -> bytes:
    key = Generator.generate_key_128b()
    header = Generator.generate_random_bytes(5, 10)
    footer = Generator.generate_random_bytes(5, 10)
    full_input = header + input + footer
    
    if randint(0, 1):
        return ("ecb", encrypt_aes_ecb(full_input, key))
    else:
        return ("cbc", encrypt_aes_cbc(full_input, key, Generator.generate_key_128b()))
        
def detect_aes_ecb_or_cbc(cipher: bytes) -> tuple[str, bytes]:
    cipher_len = len(cipher)
    n_blocks = cipher_len // 16
    chunks = Counter((cipher[i * 16 : i * 16 + 16]) for i in range(n_blocks))
    
    return ("ecb", max(chunks)) if len(chunks) != n_blocks else ("cbc", list(chunks.elements())[0])

def c11(input):
    oracle = encrypt_oracle(input)
    return (detect_aes_ecb_or_cbc(oracle[1])[0], oracle[0])