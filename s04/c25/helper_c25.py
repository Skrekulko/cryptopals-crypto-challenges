#
#   02 - Fixed XOR
#

def fixed_xor(input1: bytes, input2: bytes) -> bytes:
    if len(input1) == len(input2):
        return bytes(a ^ b for (a, b) in zip(input1, input2))
    else:
        raise ValueError

#
#   05 - Implement repeating-key XOR
#

def repeating_key_xor(input: bytes, key: bytes) -> bytes:
    repetitions = 1 + (len(input) // len(key))
    key = (key * repetitions)[:len(input)]
    
    return fixed_xor(input, key)

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
        
    @staticmethod
    def generate_random_int(min = 1, max = 32) -> int:
        return randint(min, max)

#
#   18 - Implement CTR, the stream cipher mode
#

from math import ceil
from Crypto.Cipher import AES

class AES128CTR:
    block_size = 16

    def __init__(self, key, nonce) -> None:
        self.key = key
        self.nonce = nonce
    
    @staticmethod
    def transform(input: bytes, key: bytes, nonce: int) -> bytes:
        # Counter
        counter = 0
        
        # Parse The Input Into Blocks
        n_blocks = ceil(len(input) / AES128CTR.block_size)
        in_blocks = list((input[i * AES128CTR.block_size : i * AES128CTR.block_size + AES128CTR.block_size]) for i in range(n_blocks)) 
        out_blocks = []
        
        # Transform Each Block
        for block in in_blocks:
            # Construct A Keystream
            keystream_block = AES.new(key, AES.MODE_ECB).encrypt(
                nonce.to_bytes(AES128CTR.block_size // 2, "little")
                +
                counter.to_bytes(AES128CTR.block_size // 2, "little")
            )
            
            # XOR The Keystream Block With The Input Block
            encrypted_block = repeating_key_xor(block, keystream_block)
            out_blocks.append(encrypted_block)
            
            # Increment The Counter
            counter += 1
        
        return b"".join(out_blocks)
