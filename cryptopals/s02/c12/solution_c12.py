#
#   12 - Byte-at-a-time ECB decryption (Simple)
#

from itertools import count
from cryptopals.generator import Generator
from cryptopals.symmetric import AES128ECB
from cryptopals.converter import Converter
from cryptopals.oracle import Oracle
from cryptopals.pkcs import PKCS7


class MyOracle(Oracle):
    def __init__(self):
        self.key = Generator.key_128b()
        self.target = \
            b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll" \
            b"cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

    def encrypt(self, plaintext=b"") -> bytes:
        return AES128ECB.encrypt(plaintext + self.target, self.key)
        
    def decrypt(self, encrypted_data) -> bytes:
        return AES128ECB.decrypt(encrypted_data, self.key)


class Detector:
    @staticmethod
    def block_size(oracle: Oracle) -> int:
        # Increment The Input Data Size
        for i in count(start=0):
            len1 = len(oracle.encrypt(b"A" * i))
            len2 = len(oracle.encrypt(b"A" * (i + 1)))

            # Difference Found
            if len2 > len1:
                return len2 - len1


class Decipher:
    @staticmethod
    def aes_ecb_postfix(oracle: Oracle) -> bytes:
        # Detect The Block Size And Postfix Size
        block_size = Detector.block_size(oracle)

        # Postfix Size
        postfix_size = len(oracle.encrypt(b""))

        # Extract The Postfix
        decrypted_postfix = b""
        for _ in range(postfix_size):
            # Decrypted Postfix Size
            decrypted_postfix_size = len(decrypted_postfix)

            # Crafted Padding
            crafted_padding_size = (- decrypted_postfix_size - 1) % block_size
            crafted_padding = b"A" * crafted_padding_size

            # Get The Target Block
            target_block_number = decrypted_postfix_size // block_size
            target_slice = slice(target_block_number * block_size, (target_block_number + 1) * block_size)
            target_block = oracle.encrypt(crafted_padding)[target_slice]

            # Brute-Force All The Possible Bytes
            for byte in range(256):
                crafted_input = crafted_padding + decrypted_postfix + Converter.int_to_hex(byte)
                crafted_block = oracle.encrypt(crafted_input)[target_slice]

                # Found Identical Blocks
                if crafted_block == target_block:
                    decrypted_postfix += Converter.int_to_hex(byte)
                    break

        return PKCS7.strip(decrypted_postfix, block_size)
