#
#   16 - CBC bitflipping attacks
#

from itertools import count
from cryptopals.oracle import Oracle
from cryptopals.generator import Generator
from cryptopals.pkcs import PKCS7
from cryptopals.symmetric import AES128CBC
from cryptopals.solver import Detector
from cryptopals.xor import XOR
from cryptopals.utils import Blocks


class MyOracle(Oracle):
    def __init__(self):
        self.key = Generator.key_128b()
        self.iv = Generator.key_128b()
    
    @staticmethod
    def parse_input(plaintext: bytes) -> bytes:
        # Remove Unwanted Characters ';' And '='
        filtered_plaintext = bytes(
            byte for byte in plaintext
            if byte != int.from_bytes(b";", "big") and byte != int.from_bytes(b"=", "big")
        )
        
        prefix = b"comment1=cooking%20MCs;userdata="
        postfix = b";comment2=%20like%20a%20pound%20of%20bacon"
        print(Blocks.split_into_blocks(PKCS7.padding(prefix + filtered_plaintext + postfix, AES128CBC.BLOCK_SIZE), 16))

        return PKCS7.strip(prefix + filtered_plaintext + postfix, AES128CBC.BLOCK_SIZE)
    
    @staticmethod
    def is_admin(plaintext: bytes) -> bool:
        return b";admin=true;" in plaintext
    
    def encrypt(self, plaintext=b"") -> bytes:
        return AES128CBC.encrypt(MyOracle.parse_input(plaintext), self.key, self.iv)
        
    def decrypt_and_check_admin(self, ciphertext: bytes) -> bool:
        plaintext = AES128CBC.decrypt(ciphertext, self.key, self.iv)
        print(Blocks.split_into_blocks(plaintext, 16))
        is_admin = MyOracle.is_admin(plaintext)
        
        return is_admin


class MyDetector(Detector):
    @staticmethod
    def prefix_size_cbc(oracle: Oracle, block_size: int) -> int:
        # Find Repeating Blocks With Two Identical Blocks As Input
        default_positions = Detector.block_positions(oracle.encrypt(b""), block_size)

        # Increase Until We Pad The Prefix
        for input_size in count(start=0):
            # Encrypted Plaintext
            encrypted = oracle.encrypt(
                b"A" * input_size
            )

            # Get The Positions Of The Blocks
            positions = Detector.block_positions(encrypted, block_size)

            # No New Block Appears
            if len(positions) == len(default_positions):
                continue

            # Inject Two Identical Plaintext Blocks Including The Padding
            encrypted = oracle.encrypt(
                b"A" * block_size * 2
                + b"A" * input_size
            )

            # Get Block Positions For Comparison
            default_positions = Detector.block_positions(encrypted, block_size)

            # Change Bytes Until A Change In The Blocks Occur
            old_position = None
            for j in count(start=1):
                # New Encrypted Plaintext
                encrypted = oracle.encrypt(
                    b"A" * (block_size * 2 - j)
                    + b"A" * input_size
                    + b"B" * j
                )

                # Get The Positions Of The Blocks
                positions = Detector.block_positions(encrypted, block_size)

                # Check For Corrupted Blocks
                for index, (original_block, new_block) in enumerate(zip(default_positions, positions)):
                    # Corrupted Block Found
                    if original_block != new_block:
                        # No Old Position Yet
                        if not old_position:
                            old_position = index
                            continue

                        if index < old_position:
                            return (block_size * (index + 1) + (j - 1)) - (block_size * 2 + input_size)

            raise Exception("Could not find the prefix size!")


class Decipher:
    @staticmethod
    def aes_cbc_injection(oracle: Oracle, plaintext: bytes) -> bytes:
        # Detect The Block Size
        block_size = Detector.block_size(oracle)

        # Detect The Prefix Size
        prefix_size = MyDetector.prefix_size_cbc(oracle, block_size)

        # Calculate Postfix Size
        postfix_size = Detector.postfix_size(oracle, block_size, prefix_size)

        # Unsupported Size
        if len(plaintext) > block_size:
            raise Exception("CBC injection supports only 1 block of plaintext!")

        # Pad The Plaintext From The Left
        if len(plaintext) % block_size != 0:
            plaintext = b"T" * (block_size - (len(plaintext) % block_size)) + plaintext

        # Construct Prefix And Postfix Paddings
        prefix_padding = b"P" * ((block_size - (prefix_size % block_size)) if prefix_size % block_size != 0 else 0)
        postfix_padding = b"P" * ((block_size - (postfix_size % block_size)) if postfix_size % block_size != 0 else 0)

        # Sacrificial Block
        sacrificial_block = b"S" * block_size

        # Dummy Block
        dummy_block = b"A" * block_size

        # Calculate Sacrificial And Plaintext Block Index
        sacrificial_block_index = (prefix_size + len(prefix_padding)) // block_size

        # Encrypt The Sacrificial Block + Dummy BLock
        encrypted_blocks = Blocks.split_into_blocks(
            oracle.encrypt(
                prefix_padding
                + sacrificial_block
                + dummy_block
                + postfix_padding
            ),
            block_size
        )

        # Extract The Ciphertext (Sacrificial) Block
        ciphertext_block = encrypted_blocks[sacrificial_block_index]

        # XOR The Ciphertext (Sacrificial) Block With Dummy Block
        before_xor_block = XOR.fixed(ciphertext_block, dummy_block)

        # XOR The Before XOR Block With (Known) Plaintext
        injected_block = XOR.fixed(before_xor_block, plaintext)

        # Inject The Block Into Encrypted Blocks
        injected_blocks = encrypted_blocks[:]
        injected_blocks[sacrificial_block_index] = injected_block

        return b"".join(injected_blocks)
