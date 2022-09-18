#
#   17 - The CBC padding oracle
#

import random
from itertools import count
from helper_c17 import fixed_xor, AES128CBC, Generator, PKCS7

class Oracle:
    strings = [
        b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ]
    
    def __init__(self):
        self.key = Generator.generate_key_128b()
    
    def encrypt(self) -> bytes:
        string = random.choice(Oracle.strings)
        print(len(string))
        print(string)
        iv = Generator.generate_key_128b()
        encrypted = AES128CBC.encrypt(string, self.key, iv)
        
        return {"encrypted": encrypted, "iv": iv}
        
    def decrypt(self, cipher: bytes, iv: bytes) -> (bool, bytes):
        string = AES128CBC.decrypt(cipher, self.key, iv)

def c17():
    oracle = Oracle()
    
    # Known Block Size
    block_size = 16
    
    # Get Random Cipher
    cipher = oracle.encrypt()
    encrypted = cipher["encrypted"]
    encrypted_blocks = [encrypted[i : i + block_size] for i in range(0, len(encrypted), block_size)]
    n_blocks = len(encrypted_blocks)
    iv = cipher["iv"]
    
    # Try Every Padding Length (1 - 15)
    for i in range(block_size):
        # Crafted Block
        selected_block = encrypted_blocks[n_blocks - 2]
        crafted_block = selected_block[:block_size - (i + 1)] + b"\xff" + selected_block[block_size - i:]
        
        # Flipping
        flipped_blocks = encrypted_blocks[:]
        flipped_blocks[n_blocks - 2] = crafted_block
        flipped = b"".join(flipped_blocks)
    
        try:
            print(i)
            print(encrypted_blocks[n_blocks - 2])
            print(flipped_blocks[n_blocks - 2])
            oracle.decrypt(encrypted, iv)
            oracle.decrypt(flipped, iv)
        except ValueError:
            continue

    return False