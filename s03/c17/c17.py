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
        print(PKCS7.padding(string, 16))
        iv = Generator.generate_key_128b()
        encrypted = AES128CBC.encrypt(string, self.key, iv)
        
        return {"encrypted": encrypted, "iv": iv}
        
    def decrypt(self, cipher: bytes, iv: bytes) -> (bool, bytes):
        string = AES128CBC.decrypt(cipher, self.key, iv)

from Crypto.Cipher import AES

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
    
    # [Refactored] Find Initial Padding Size
    padding_size = 0
    for i in range(block_size):
        # Previous Ciphertext Block
        previous_block = encrypted_blocks[-2]
        
        # Predicted Padding Byte And Incorrect Padding Byte
        predicted_byte = (block_size - i).to_bytes(1, "big")
        incorrect_byte = ((block_size - i) + 1).to_bytes(1, "big")
        
        # Corresponding Byte Of Previous Ciphertext Block
        previous_byte = previous_block[i].to_bytes(1, "big")
        
        # Before XOR Byte Of Current Ciphertext Block
        before_xor_byte = fixed_xor(previous_byte, predicted_byte)
        
        # Crafted Byte And Block
        crafted_byte = fixed_xor(before_xor_byte, incorrect_byte)
        crafted_block = previous_block[:i] + crafted_byte + previous_block[(i + 1):]
    
        # Bit-Flipping
        flipped_blocks = encrypted_blocks[:]
        flipped_blocks[-2] = crafted_block
        flipped_cipher = b"".join(flipped_blocks)
    
        try:
            oracle.decrypt(flipped_cipher, iv)
            continue
        except ValueError:
            padding_size = block_size - i
            break
    
    print(f"found padding length = {padding_length}")
    print(f"found padding size = {padding_size}")
        
    exit()
    # Decrypt With Known Padding
    decrypted_block = b""
    to_xor = encrypted_blocks[n_blocks - 2][block_size - padding_length:]
    padding = padding_length.to_bytes(1, "big") * padding_length
    decrypted_block = fixed_xor(to_xor, padding)
    
    # Byte Position
    for i in range(block_size):
        # Crafted Padding
        current_padding_length = padding_length + (i + 1)
        crafted_padding = current_padding_length.to_bytes(1, "big") * padding_length
        
        # Bit-Flipping (256 Different Combinations)
        for j in range(255):
            # XORed Bytes
            xored_bytes = fixed_xor(crafted_padding, decrypted_block)
            
            # Crafted Bytes
            crafted_bytes = j.to_bytes(1, "big") + xored_bytes
            
            # Bit-Flipped Block
            flipped_block = b"\x00" * (block_size - len(crafted_bytes)) + crafted_bytes
            
            # Bit-Flipped Cipher
            flipped_blocks = encrypted_blocks[:]
            flipped_blocks[-2] = flipped_block
            flipped_cipher = b"".join(flipped_blocks)
            
            # Decrypt And Check Padding
            try:
                oracle.decrypt(flipped_cipher, iv)
                found_byte = j.to_bytes(1, "big")
                padding_byte = current_padding_length.to_bytes(1, "big")
                decrypted_byte = fixed_xor(found_byte, padding_byte)
                decrypted_block = decrypted_byte + decrypted_block
                print(decrypted_block)
                break
            except ValueError:
                continue
            
        break
    return False