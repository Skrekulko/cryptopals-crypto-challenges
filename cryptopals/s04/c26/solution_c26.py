#
#   26 - CTR bitflipping
#

from cryptopals.oracle import Oracle
from cryptopals.generator import Generator
from cryptopals.symmetric import AES128CTR
from cryptopals.xor import XOR


class MyOracle(Oracle):
    def __init__(self):
        self.key = Generator.key_128b()
        self.nonce = Generator.random_int(1, (1 << 16) - 1)
    
    @staticmethod
    def parse_input(plaintext: bytes) -> bytes:
        # Remove Unwanted Characters ';' And '='
        plaintext = bytes(
            byte for byte in plaintext
            if byte != int.from_bytes(b";", "big") and byte != int.from_bytes(b"=", "big")
        )
        
        prefix = b"comment1=cooking%20MCs;userdata="
        postfix = b";comment2=%20like%20a%20pound%20of%20bacon"

        return prefix + plaintext + postfix
    
    @staticmethod
    def is_admin(plaintext: bytes) -> bool:
        return b";admin=true;" in plaintext
    
    def encrypt(self, plaintext=b"") -> bytes:
        return AES128CTR.transform(MyOracle.parse_input(plaintext), self.key, self.nonce)
        
    def decrypt(self, ciphertext=b"", key=b"", iv=b"") -> bytes:
        plaintext = AES128CTR.transform(ciphertext, self.key, self.nonce)
        
        return plaintext


class Detector:
    @staticmethod
    def prefix_size_ctr(oracle: Oracle) -> int:
        # No Input (Empty) Ciphertext
        ciphertext_empty = oracle.encrypt(b"")

        # Ciphertext With At Least One Byte Difference
        ciphertext_diff = oracle.encrypt(b"A")

        # Compare The Bytes For Difference
        for index, (byte1, byte2) in enumerate(zip(ciphertext_empty, ciphertext_diff)):
            if byte1 != byte2:
                return index

        # No Difference Means That There's No Postfix
        return len(ciphertext_empty)


class Decipher:
    @staticmethod
    def aes_ctr_injection(oracle: Oracle, plaintext: bytes) -> bytes:
        # Prefix Size
        prefix_size = Detector.prefix_size_ctr(oracle)

        # Sacrificial Plaintext
        sacrificial_plaintext = b"A" * len(plaintext)

        # Sacrificial Ciphertext
        ciphertext = oracle.encrypt(sacrificial_plaintext)
        sacrificial_ciphertext = oracle.encrypt(sacrificial_plaintext)[prefix_size:prefix_size + len(plaintext)]

        # Calculate Keystream Bytes
        keystream = XOR.fixed(sacrificial_ciphertext, sacrificial_plaintext)

        # XOR The Keystream With The Plaintext
        xored = XOR.fixed(keystream, plaintext)

        # Modify Encrypted Data
        modified_ciphertext = ciphertext[:prefix_size] + xored + ciphertext[prefix_size + len(plaintext):]

        return modified_ciphertext
