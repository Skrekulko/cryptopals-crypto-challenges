#
#   07 - AES in ECB mode
#

from Crypto.Cipher import AES
from cryptopals.utils import Blocks, Converter


class PKCS7:
    @staticmethod
    def padding(data: bytes, block_size: int) -> bytes:
        padding_length = block_size - (len(data) % block_size)

        if padding_length == block_size:
            return data

        return data + padding_length * Converter.int_to_hex(padding_length)

    @staticmethod
    def strip(padded_data: bytes, block_size: int) -> bytes:
        last_byte = padded_data[-1]

        if last_byte > block_size:
            return padded_data

        if padded_data[-last_byte:] != last_byte * Converter.int_to_hex(last_byte):
            raise ValueError("Incorrect padding.")

        return padded_data[:-last_byte]


class AES128ECB:
    # Block Size Of 16 Bytes (128 Bits)
    BLOCK_SIZE = 16

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        # Pad The Plaintext
        padded_input = PKCS7.padding(plaintext, AES128ECB.BLOCK_SIZE)

        # Calculate The Total Amount Of Blocks
        n_blocks = Blocks.number_of_blocks(padded_input, AES128ECB.BLOCK_SIZE)

        # Parse Into Blocks
        in_blocks = Blocks.split_into_blocks(padded_input, AES128ECB.BLOCK_SIZE, n_blocks)

        # Encrypt The Blocks Using The Secret Key
        out_blocks = [AES.new(key, AES.MODE_ECB).encrypt(in_block) for in_block in in_blocks]

        # Put The Blocks Together
        return b"".join(out_blocks)

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        # Calculate The Total Amount Of Blocks
        n_blocks = Blocks.number_of_blocks(encrypted_data, AES128ECB.BLOCK_SIZE)

        # Parse Into Blocks
        in_blocks = Blocks.split_into_blocks(encrypted_data, AES128ECB.BLOCK_SIZE, n_blocks)

        # Decrypt The Blocks Using The Secret Key
        out_blocks = [AES.new(key, AES.MODE_ECB).decrypt(in_block) for in_block in in_blocks]

        # Put The Blocks Together And Strip The Padding
        return PKCS7.strip(b"".join(out_blocks), AES128ECB.BLOCK_SIZE)
