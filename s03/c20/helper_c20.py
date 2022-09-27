#
#   02 - Fixed XOR
#

def fixed_xor(input1: bytes, input2: bytes) -> bytes:
    if len(input1) == len(input2):
        return bytes(a ^ b for (a, b) in zip(input1, input2))
    else:
        raise ValueError

#
#   03 - Single-byte XOR cipher
#

from collections import Counter

occurance_english = {
    'a': 8.2389258,    'b': 1.5051398,
    'c': 2.8065007,    'd': 4.2904556,
    'e': 12.813865,    'f': 2.2476217,
    'g': 2.0327458,    'h': 6.1476691,
    'i': 6.1476691,    'j': 0.1543474,
    'k': 0.7787989,    'l': 4.0604477,
    'm': 2.4271893,    'n': 6.8084376,
    'o': 7.5731132,    'p': 1.9459884,
    'q': 0.0958366,    'r': 6.0397268,
    's': 6.3827211,    't': 9.1357551,
    'u': 2.7822893,    'v': 0.9866131,
    'w': 2.3807842,    'x': 0.1513210,
    'y': 1.9913847,    'z': 0.0746517
}

dist_english = list(occurance_english.values())

def single_byte_xor(input: bytes, key: int) -> bytes:
    return bytes((byte ^ key) for byte in input)

def compute_fitting_quotient(text: bytes) -> float:
    counter = Counter(text)
    dist_text = [
        (counter.get(ord(ch), 0) * 100) / len(text)
        for ch in occurance_english
    ]
    
    return sum([abs(a - b) for a, b in zip(dist_english, dist_text)]) / len(dist_text)

def single_byte_xor_decipher(input: bytes) -> tuple[bytes, int, float]:
    original_text, encryption_key, min_fq = None, None, None
    
    for k in range(256):
        _input = single_byte_xor(input, k)
        _freq = compute_fitting_quotient(_input)

        if min_fq is None or _freq < min_fq:
            encryption_key, original_text, min_fq = k, _input, _freq
    
    return original_text, encryption_key, min_fq

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

#
#   18 - Implement CTR, the stream cipher mode
#

from math import ceil
from Crypto.Cipher import AES

class AES128CTR:
    block_size = 16

    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce

    def transform(self, input: bytes) -> bytes:
        # Counter
        counter = 0
        
        # Parse The Input Into Blocks
        n_blocks = ceil(len(input) / AES128CTR.block_size)
        in_blocks = list((input[i * AES128CTR.block_size : i * AES128CTR.block_size + AES128CTR.block_size]) for i in range(n_blocks)) 
        out_blocks = []
        
        # Transform Each Block
        for block in in_blocks:
            # Construct A Keystream
            keystream_block = AES.new(self.key, AES.MODE_ECB).encrypt(
                self.nonce.to_bytes(AES128CTR.block_size // 2, "little")
                +
                counter.to_bytes(AES128CTR.block_size // 2, "little")
            )
            
            # XOR The Keystream Block With The Input Block
            encrypted_block = repeating_key_xor(block, keystream_block)
            out_blocks.append(encrypted_block)
            
            # Increment The Counter
            counter += 1
        
        return b"".join(out_blocks)