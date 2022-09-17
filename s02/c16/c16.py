#
#   16 - CBC bitflipping attacks
#

from helper_c16 import fixed_xor, AES128CBC, Generator, PKCS7
from itertools import count

class Oracle:
    def __init__(self):
        self.key = Generator.generate_key_128b()
        self.iv = Generator.generate_key_128b()
    
    @staticmethod
    def parse_input(input: bytes) -> bytes:
        # Remove Unwated Characters ';' And '='
        filtered_input = bytes(byte for byte in input if byte != int.from_bytes(b";", "big") and byte != int.from_bytes(b"=", "big"))
        
        to_prepend = b"comment1=cooking%20MCs;userdata="
        to_append = b";comment2=%20like%20a%20pound%20of%20bacon"
        return PKCS7.strip(to_prepend + filtered_input + to_append, AES128CBC.block_size)
    
    @staticmethod
    def is_admin(input: bytes) -> bool:
        return b";admin=true;" in input
    
    def encrypt(self, input: bytes) -> bytes:
        return AES128CBC.encrypt(Oracle.parse_input(input), self.key, self.iv)
        
    def decrypt_and_check_admin(self, encrypted_input: bytes) -> (bool, bytes):
        decrypted = AES128CBC.decrypt(encrypted_input, self.key, self.iv)
        is_admin = Oracle.is_admin(decrypted)
        
        return {"admin": is_admin, "decrypted": decrypted}

def c16():
    oracle = Oracle()
    
    # Detect Block Size And Required Padding Length For A New Block
    block_size = 0
    required_padding_len = 0
    no_input_length = len(oracle.encrypt(b""))
    for i in count(start = 0):
        length = len(oracle.encrypt(b"A" * i))
        
        if length != no_input_length:
            block_size = length - no_input_length
            required_padding_len = i - 1
            break
    
    # Crafted Admin
    admin = b";admin=true"
    admin_len = len(admin)
    crafted_admin = b"A" * (block_size - admin_len) + admin
    
    # Crafted Input
    crafted_len = (block_size * 2)
    crafted_input = b"A" * crafted_len
    
    # Reverse Crafted Input
    encrypted = oracle.encrypt(crafted_input)
    encrypted_blocks = [encrypted[i : i + block_size] for i in range(0, len(encrypted), block_size)]
    before_xor = fixed_xor(encrypted_blocks[2], b"A" * block_size)
    crafted_block = fixed_xor(before_xor, crafted_admin)
    
    # Bit-Flipping
    flipped_blocks = encrypted_blocks[:]
    flipped_blocks[2] = crafted_block
    flipped = b"".join(flipped_blocks)
    decrypted = oracle.decrypt_and_check_admin(flipped)
    
    return decrypted["admin"]