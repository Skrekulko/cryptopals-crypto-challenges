#
#   09 - Implement PKCS#7 padding
#

from cryptopals.utils import Converter


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
