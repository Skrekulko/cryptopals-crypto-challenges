#
#   14 - Byte-at-a-time ECB decryption (Harder)
#

from itertools import count
from helper_c14 import Generator, encrypt_aes_ecb, detect_aes_ecb_or_cbc

class Oracle:
    def __init__(self):
        self.key = Generator.generate_key_128b()
        self.prefix = Generator.generate_random_bytes()
        self.target = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

    def encrypt_prefix(self, input = b"") -> bytes:
        return encrypt_aes_ecb(self.prefix + input + self.target, self.key)
        
    def decrypt(self, input) -> bytes:
        return decrypt_aes_ecb(input, self.key)

def crack_oracle_prefix() -> bytes:
    oracle = Oracle()
    
    # Detect Block Size
    block_size = 0
    no_input_length = len(oracle.encrypt_prefix())
    for i in count(start = 0):
        length = len(oracle.encrypt_prefix(b"A" * i))
        
        if length != no_input_length:
            block_size = length - no_input_length
            required_padding_len = i - 1
            break
    
    # Detect Encryption Mode
    detection_padding = b"A" * block_size * 2 + b"A" * (required_padding_len + 1)
    detected_mode = detect_aes_ecb_or_cbc(oracle.encrypt_prefix(detection_padding))
    
    # Calculate Prefix Size
    prefix_size = 0
    previous_blocks = []
    for i in range(0, block_size):
        cipher = oracle.encrypt_prefix(b"A" * i)
        current_blocks = list(cipher[i * block_size : i * block_size + block_size] for i in range(len(cipher) // block_size))
        
        if previous_blocks and current_blocks[0] == previous_blocks[0]:
            prefix_size = block_size - i + 1
            break
            
        previous_blocks = current_blocks
    
    # Calculate Target Length
    target_length = no_input_length - required_padding_len - prefix_size
    
    # Extract The Unknown Input
    decrypted = b""
    for _ in range(target_length):
        # Craft The Needed Padding
        decrypted_len = len(decrypted)
        padding_len = (- decrypted_len - 1 - prefix_size) % block_size
        padding = b"A" * padding_len
        
        # Calculate And Get The Target Block
        target_block_number = (decrypted_len + prefix_size) // block_size
        target_slice = slice(target_block_number * block_size, (target_block_number + 1) * block_size)
        target_block = oracle.encrypt_prefix(padding)[target_slice]
        
        # Brute-Force All Possible Combinations For A Single Byte
        for byte in range(256):
            crafted_input = padding + decrypted + byte.to_bytes(1, "big")
            crafted_block = oracle.encrypt_prefix(crafted_input)[target_slice]
            
            # Match Found
            if crafted_block == target_block:
                decrypted += byte.to_bytes(1, "little")
                break
    
    return decrypted

def c14():
    return crack_oracle_prefix()
