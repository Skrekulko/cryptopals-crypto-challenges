#
#   12 - Byte-at-a-time ECB decryption (Simple)
#

from itertools import count
from helper_c12 import Generator, encrypt_aes_ecb, detect_aes_ecb_or_cbc

class Oracle:
    def __init__(self):
        self.key = Generator.generate_key_128b()
        self.prefix = Generator.generate_random_bytes()
        self.target = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

    def encrypt_no_prefix(self, input = b"") -> bytes:
        return encrypt_aes_ecb(input + self.target, self.key)
        
    def decrypt(self, input) -> bytes:
        return decrypt_aes_ecb(input, self.key)

def crack_oracle_no_prefix() -> bytes:
    oracle = Oracle()
    
    # Detect Block Size
    block_size = 0
    target_length = 0
    required_padding_len = 0
    for i in count(start = 0):
        encrypted1_len = len(oracle.encrypt_no_prefix(b"A" * i))
        encrypted2_len = len(oracle.encrypt_no_prefix(b"A" * (i + 1)))
        
        if encrypted2_len > encrypted1_len:
            block_size = encrypted2_len - encrypted1_len
            target_length = encrypted1_len - i
            required_padding_len = i
            break
    
    # Detect Encryption Mode
    detection_padding = b"A" * block_size * 2 + b"A" * (required_padding_len + 1)
    detected_mode = detect_aes_ecb_or_cbc(oracle.encrypt_no_prefix(detection_padding))
    
    # Extract The Unknown Input
    decrypted = b""
    for _ in range(target_length):
        # Craft The Needed Padding
        decrypted_len = len(decrypted)
        padding_len = (- decrypted_len - 1) % block_size
        padding = b"A" * padding_len
        
        # Calculate And Get The Target Block
        target_block_number = decrypted_len // block_size
        target_slice = slice(target_block_number * block_size, (target_block_number + 1) * block_size)
        target_block = oracle.encrypt_no_prefix(padding)[target_slice]
        
        # Brute-Force All Possible Combinations For A Single Byte
        for byte in range(256):
            crafted_input = padding + decrypted + byte.to_bytes(1, "big")
            crafted_block = oracle.encrypt_no_prefix(crafted_input)[target_slice]
            
            # Match Found
            if crafted_block == target_block:
                decrypted += byte.to_bytes(1, "little")
                break
                
    return decrypted

def c12():
    return crack_oracle_no_prefix()
