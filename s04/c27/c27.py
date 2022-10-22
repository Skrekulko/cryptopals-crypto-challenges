#
#   27 - Recover the key from CBC with IV=Key
#

from helper_c27 import fixed_xor, AES128CBC, Generator, PKCS7
from itertools import count

class Oracle:
    def __init__(self):
        # IV = Key
        self.key = Generator.generate_key_128b()
        self.iv = self.key
    
    @staticmethod
    def parse_input(plaintext: bytes) -> bytes:
        # Remove Unwated Characters ';' And '='
        filtered_input = bytes(byte for byte in plaintext if byte != int.from_bytes(b";", "big") and byte != int.from_bytes(b"=", "big"))
        
        to_prepend = b"comment1=cooking%20MCs;userdata="
        to_append = b";comment2=%20like%20a%20pound%20of%20bacon"
        return PKCS7.strip(to_prepend + filtered_input + to_append, AES128CBC.block_size)
    
    @staticmethod
    def ascii_compliance(plaintext: bytes) -> bool:
        return all(c >= 128 for c in plaintext)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        return AES128CBC.encrypt(Oracle.parse_input(plaintext), self.key, self.iv)
        
    def decrypt_and_check_admin(self, ciphertext: bytes) -> (bool, bytes):
        plaintext = AES128CBC.decrypt(ciphertext, self.key, self.iv)
        
        if not Oracle.ascii_compliance(plaintext):
            raise Exception("High ASCII values found!", plaintext)
        
        return b";admin=true;" in plaintext

def find_block_size(oracle: Oracle) -> int:
    # Increase The Plaintext Until The Ciphertext Size Increases
    for i in count(start = 0):
        ciphertext_a = oracle.encrypt(b"A" * i)
        ciphertext_b = oracle.encrypt(b"A" * (i + 1))
        
        # Different Ciphertext Sizes
        if len(ciphertext_a) != len(ciphertext_b):
            block_size = len(ciphertext_b) - len(ciphertext_a)
            required_padding_len = i - 1
            
            return block_size

def find_prefix_size(oracle: Oracle, block_size: int) -> int:
    # Encrypt Two Different Plaintexts
    ciphertext_a = oracle.encrypt(b"A")
    ciphertext_b = oracle.encrypt(b"B")
    
    # Common Number Of Bytes
    common_length = 0
    while ciphertext_a[common_length] == ciphertext_b[common_length]:
        common_length += 1
    
    # Multiple Of The Block Length
    common_length = (common_length // block_size) * block_size
    
    # Increase The Plaintext Until One They Have One Extra Identical Block
    for i in range(1, block_size + 1):
        ciphertext_a = oracle.encrypt(b"A" * i + b"X")
        ciphertext_b = oracle.encrypt(b"A" * i + b"Y")
        
        # Identical Block Found
        if (
            ciphertext_a[common_length : common_length + block_size]
            ==
            ciphertext_b[common_length : common_length + block_size]
        ):
            return common_length + (block_size - i)
    
def oracle_crack_key_iv(oracle: Oracle) -> bool:
    # Detect Block Size
    block_size = find_block_size(oracle)
    
    # Detect Prefix Size
    prefix_size = find_prefix_size(oracle, block_size)
    
    # Crafted Blocks
    crafted_a = b"A" * block_size
    crafted_b = b"B" * block_size
    crafted_c = b"C" * block_size
    crafted_null = b"\x00" * block_size
    
    # (P_1, P_2, P_3) -> (C_1, C_2, C_3)
    ciphertext = oracle.encrypt(crafted_a + crafted_b + crafted_c)
    
    # (C_1, C_2, C_3) -> (C_1, 0, C_3)
    forced_ciphertext = (
        ciphertext[prefix_size : prefix_size + block_size]
        +
        crafted_null
        +
        ciphertext[prefix_size : prefix_size + block_size]
    )
    
    # Try To Decrypt
    try:
        oracle.decrypt_and_check_admin(forced_ciphertext)
    except Exception as e:
        forced_plaintext = e.args[1]
        
        # (P'_1 XOR P'_3)
        return fixed_xor(forced_plaintext[:block_size], forced_plaintext[-block_size:])

    raise Exception("Not able to get the key!")

def c27(oracle: Oracle):
    return oracle_crack_key_iv(oracle)