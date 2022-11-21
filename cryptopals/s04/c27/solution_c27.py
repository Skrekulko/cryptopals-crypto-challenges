#
#   27 - Recover the key from CBC with IV=Key
#

from cryptopals.oracle import Oracle
from cryptopals.generator import Generator
from cryptopals.pkcs import PKCS7
from cryptopals.symmetric import AES128CBC
from cryptopals.solver import Detector
from cryptopals.xor import XOR


class MyOracle(Oracle):
    def __init__(self):
        # IV = Key
        self.key = Generator.key_128b()
        self.iv = self.key
    
    @staticmethod
    def parse_input(plaintext: bytes) -> bytes:
        # Remove Unwanted Characters ';' And '='
        filtered_input = bytes(
            byte for byte in plaintext
            if byte != int.from_bytes(b";", "big") and byte != int.from_bytes(b"=", "big")
        )
        
        prefix = b"comment1=cooking%20MCs;userdata="
        postfix = b";comment2=%20like%20a%20pound%20of%20bacon"

        return PKCS7.strip(prefix + filtered_input + postfix, AES128CBC.BLOCK_SIZE)
    
    @staticmethod
    def ascii_compliance(plaintext: bytes) -> bool:
        return all(c >= 128 for c in plaintext)
    
    def encrypt(self, plaintext=b"") -> bytes:
        return AES128CBC.encrypt(MyOracle.parse_input(plaintext), self.key, self.iv)
        
    def decrypt(self, ciphertext=b"", key=b"", iv=b"") -> bytes:
        plaintext = AES128CBC.decrypt(ciphertext, self.key, self.iv)
        
        if not MyOracle.ascii_compliance(plaintext):
            raise Exception("High ASCII values found!", plaintext)
        
        return plaintext


class Decipher:
    @staticmethod
    def aes_cbc_iv_key(oracle: Oracle) -> bytes:
        # Detect Block Size
        block_size = Detector.block_size(oracle)

        # Detect Prefix Size
        prefix_size = Detector.prefix_size_cbc(oracle, block_size)

        # Crafted Blocks
        crafted_a = b"A" * block_size
        crafted_b = b"B" * block_size
        crafted_c = b"C" * block_size
        crafted_null = b"\x00" * block_size

        # (P_1, P_2, P_3) -> (C_1, C_2, C_3)
        ciphertext = oracle.encrypt(crafted_a + crafted_b + crafted_c)

        # (C_1, C_2, C_3) -> (C_1, 0, C_3)
        forced_ciphertext = (
            ciphertext[prefix_size:prefix_size + block_size]
            +
            crafted_null
            +
            ciphertext[prefix_size:prefix_size + block_size]
        )

        # Try To Decrypt
        try:
            oracle.decrypt(forced_ciphertext)
        except Exception as e:
            forced_plaintext = e.args[1]

            # (P'_1 XOR P'_3)
            return XOR.fixed(forced_plaintext[:block_size], forced_plaintext[-block_size:])

        raise Exception("Not able to get the key!")
