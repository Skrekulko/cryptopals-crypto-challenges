#
#   17 - The CBC padding oracle
#

import random

from cryptopals.Oracle import Oracle
from cryptopals.Generator import Generator
from cryptopals.symmetric import AES128CBC
from cryptopals.XOR import XOR
from cryptopals.PKCS import PKCS7


class MyOracle(Oracle):
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
        self.key = Generator.key_128b()

    def encrypt(self, plaintext=b"") -> tuple[bytes, bytes]:
        # Pick A Random Plaintext String
        string = random.choice(MyOracle.strings)

        # Generate An IV
        iv = Generator.key_128b()

        # Encrypted The Plaintext String
        ciphertext = AES128CBC.encrypt(string, self.key, iv)

        return ciphertext, iv

    def decrypt(self, ciphertext=b"", key=b"", iv=b"") -> bytes:
        # Decrypt The Ciphertext And Expect An Error
        ciphertext = AES128CBC.decrypt(ciphertext, self.key, iv)

        return ciphertext

    def check_string(self, plaintext: bytes) -> bool:
        if plaintext in self.strings:
            return True
        else:
            return False


class Decipher:
    @staticmethod
    def cbc_random_padding_size(oracle: Oracle, ciphertext_block: bytes, iv: bytes, block_size: int) -> int:
        # Initial Padding Size
        padding_size = 0

        # Iterate Through All Possible Padding Sizes
        for i in range(block_size):
            # Predicted Padding Byte And Incorrect Padding Byte
            predicted_byte = (block_size - i).to_bytes(1, "big")
            incorrect_byte = ((block_size - i) + 1).to_bytes(1, "big")

            # Corresponding Byte Of The IV
            iv_byte = iv[i].to_bytes(1, "big")

            # Before XOR Byte Of Current Ciphertext Block
            before_xor_byte = XOR.fixed(iv_byte, predicted_byte)

            # Crafted Byte And Block
            crafted_byte = XOR.fixed(before_xor_byte, incorrect_byte)
            crafted_block = iv[:i] + crafted_byte + iv[(i + 1):]

            # Bit-Flipping
            flipped_cipher = crafted_block + ciphertext_block

            # Try Decrypting Using The Oracle
            try:
                oracle.decrypt(flipped_cipher, b"", iv)
                continue
            # Incorrect Padding
            except ValueError:
                padding_size = block_size - i
                break

        return padding_size

    @staticmethod
    def cbc_brute_force_random_padding(oracle: Oracle, ciphertext_block: bytes, iv: bytes) -> bytes:
        # Brute-Force Last Padding Byte
        for i in range(256):
            # Crafted IV
            crafted_byte = i.to_bytes(1, "big")
            crafted_iv = iv[:-1] + crafted_byte

            # Try To Decrypt And Check Last Padding For '\x02'
            try:
                oracle.decrypt(ciphertext_block, b"", crafted_iv)
            except ValueError:
                # Brute-Force Previous Byte
                for j in range(256):
                    # Crafted Previous Padding Byte
                    crafted_previous_byte = j.to_bytes(1, "big")

                    # Crafted IV
                    crafted_iv = iv[:-2] + crafted_previous_byte + crafted_byte

                    # Try To Decrypt And Check '\x02\x02' Padding
                    try:
                        oracle.decrypt(ciphertext_block, b"", crafted_iv)

                        # Corrupted Padding
                        before_xor_byte = XOR.fixed(iv[-2].to_bytes(1, "big"), b"\x02")
                        xored_byte = XOR.fixed(before_xor_byte, b"\x03")
                        crafted_iv = iv[:-2] + xored_byte + crafted_byte

                        # Try To Decrypt And Check Corrupted '\x03\x02' Padding
                        try:
                            oracle.decrypt(ciphertext_block, b"", crafted_iv)
                        except ValueError:
                            before_xor_bytes = XOR.fixed(b"\x02\x02", crafted_previous_byte + crafted_byte)
                            return before_xor_bytes
                    except ValueError:
                        continue
                continue
            # Previous Padding Byte May Be '\x02'
            else:
                # Corrupted Padding
                before_xor_byte = XOR.fixed(iv[-2].to_bytes(1, "big"), b"\x02")
                xored_byte = XOR.fixed(before_xor_byte, b"\x03")
                crafted_iv = iv[:-2] + xored_byte + crafted_byte

                # Try To Decrypt And Check Corrupted '\x03\x02' Padding
                try:
                    oracle.decrypt(ciphertext_block, b"", crafted_iv)
                except ValueError:
                    before_xor_bytes = XOR.fixed(b"\x02\x02", iv[-2].to_bytes(1, "big") + crafted_byte)
                    return before_xor_bytes

                continue

        raise Exception("Could not brute-force the padding!")

    @staticmethod
    def cbc_padding_oracle(oracle: Oracle):
        # Known Block Size
        block_size = 16

        # Get Random Cipher
        cipher = oracle.encrypt()
        encrypted, iv = cipher

        # Put Together The Ciphertext Blocks With IV
        ciphertext_blocks = [encrypted[i: i + block_size] for i in range(0, len(encrypted), block_size)]
        ciphertext_blocks = [iv] + ciphertext_blocks
        n_blocks = len(ciphertext_blocks)

        decrypted = b""

        # Traverse All The Ciphertext Blocks (Skipping Initial IV)
        for i in range(n_blocks - 1, 0, -1):
            # Current Ciphertext Block
            ciphertext_block = ciphertext_blocks[i]

            # Previous Ciphertext Block (IV)
            iv = ciphertext_blocks[i - 1]

            # Find Padding Size Of The Current Ciphertext Block
            padding_size = Decipher.cbc_random_padding_size(
                oracle,
                ciphertext_block,
                iv,
                block_size
            )

            # If Padding Size Is Not Zero
            if padding_size != 0:
                before_xor_bytes = XOR.fixed(
                    iv[-padding_size:],
                    padding_size.to_bytes(1, "big") * padding_size
                )
            else:
                # Brute-Force Initial Padding
                before_xor_bytes = Decipher.cbc_brute_force_random_padding(
                    oracle,
                    ciphertext_block,
                    iv
                )

                padding_size = len(before_xor_bytes)

            # Ciphertext Block Byte Position (Skipping Known Padding)
            for j in range(padding_size, block_size):
                # Crafted Padding (Without The nth Byte)
                padding = (j + 1).to_bytes(1, "big") * j

                # XORed Bytes
                xored_bytes = XOR.fixed(padding, before_xor_bytes)

                # Brute-Force Bit-Flipping For New Padding Byte
                for k in range(256):

                    # Crafted IV
                    crafted_iv = iv[:-(j + 1)] + k.to_bytes(1, "big") + xored_bytes

                    # Try To Decrypt And Check Padding
                    try:
                        oracle.decrypt(ciphertext_block, b"", crafted_iv)
                        before_xor_byte = XOR.fixed(k.to_bytes(1, "big"), (j + 1).to_bytes(1, "big"))
                        before_xor_bytes = before_xor_byte + before_xor_bytes
                        break
                    except ValueError:
                        continue

            decrypted = XOR.fixed(iv, before_xor_bytes) + decrypted

        return PKCS7.strip(decrypted, block_size)
