#
#   02 - Fixed XOR
#

def fixed_xor(input1: bytes, input2: bytes) -> bytes:
    if len(input1) == len(input2):
        return bytes(a ^ b for (a, b) in zip(input1, input2))
    else:
        raise ValueError

#
#   10 - Implement CBC mode
#

from Crypto.Cipher import AES

class AES128CBC:
    # Class Variables
    block_size = 16
    
    @staticmethod
    def encrypt(input: bytes, key: bytes, iv: bytes) -> bytes:
        padded_input = PKCS7.padding(input, AES128CBC.block_size)
        n_blocks = int(len(padded_input) / AES128CBC.block_size)
        in_blocks = list((padded_input[i * AES128CBC.block_size : i * AES128CBC.block_size + AES128CBC.block_size]) for i in range(n_blocks)) 
        out_blocks = []
        
        # First Block (Using IV)
        out_blocks.append(AES.new(key, AES.MODE_ECB).encrypt(fixed_xor(in_blocks[0], iv)))
        
        for i in range(1, n_blocks):
            out_blocks.append(AES.new(key, AES.MODE_ECB).encrypt(fixed_xor(in_blocks[i], out_blocks[i - 1])))

        return b"".join(out_blocks)
        
    @staticmethod
    def decrypt(input: bytes, key: bytes, iv: bytes) -> bytes:
        n_blocks = int(len(input) / AES128CBC.block_size)
        in_blocks = list((input[i * AES128CBC.block_size : i * AES128CBC.block_size + AES128CBC.block_size]) for i in range(n_blocks))   
        out_blocks = []
        
        # First Block (Using IV)
        out_blocks.append(fixed_xor(AES.new(key, AES.MODE_ECB).decrypt(in_blocks[0]), iv))
        
        for i in range(1, n_blocks):
            out_blocks.append(fixed_xor(AES.new(key, AES.MODE_ECB).decrypt(in_blocks[i]), in_blocks[i - 1]))
        
        return PKCS7.strip(b"".join(out_blocks), AES128CBC.block_size)

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

#
#   15 - PKCS#7 padding validation
#

class PKCS7:
    @staticmethod
    def padding(input: bytes, block_size: int) -> bytes:
        padding_length = block_size - (len(input) % block_size)
        
        if padding_length == block_size:
            return input
        
        return input + padding_length * padding_length.to_bytes(1, "big")
        
    @staticmethod
    def strip(input: bytes, block_size: int) -> bytes:
        last_byte = input[-1]
        
        if last_byte > block_size:
            return input
        
        if input[-last_byte:] != last_byte * last_byte.to_bytes(1, "big"):
            raise ValueError("Incorrect padding.")

        return input[:-last_byte]
