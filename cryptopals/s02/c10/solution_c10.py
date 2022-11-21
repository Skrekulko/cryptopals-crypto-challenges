from Crypto.Cipher import AES
from cryptopals.PKCS import PKCS7
from cryptopals.XOR import XOR
from cryptopals.utils import Blocks


class AES128CBC:
    # Block Size Of 16 Bytes (128 Bits)
    BLOCK_SIZE = 16

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        # Pad The Plaintext
        padded_input = PKCS7.padding(plaintext, AES128CBC.BLOCK_SIZE)

        # Calculate The Total Amount Of Blocks
        n_blocks = Blocks.number_of_blocks(padded_input, AES128CBC.BLOCK_SIZE)

        # Parse Into Blocks
        in_blocks = Blocks.split_into_blocks(padded_input, AES128CBC.BLOCK_SIZE, n_blocks)

        # Encrypt The First Block Using The IV
        out_blocks = [AES.new(key, AES.MODE_ECB).encrypt(XOR.fixed(in_blocks[0], iv))]

        # Encrypt The Next Block Using The Previous Block
        for i in range(1, n_blocks):
            out_blocks.append(AES.new(key, AES.MODE_ECB).encrypt(XOR.fixed(in_blocks[i], out_blocks[i - 1])))

        # Put The Blocks Together
        return b"".join(out_blocks)

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
        # Calculate The Total Amount Of Blocks
        n_blocks = Blocks.number_of_blocks(encrypted_data, AES128CBC.BLOCK_SIZE)

        # Parse Into Blocks
        in_blocks = Blocks.split_into_blocks(encrypted_data, AES128CBC.BLOCK_SIZE, n_blocks)

        # Decrypt The First Block Using The IV
        out_blocks = [XOR.fixed(AES.new(key, AES.MODE_ECB).decrypt(in_blocks[0]), iv)]

        # Dencrypt The Next Block Using The Previous Block
        for i in range(1, n_blocks):
            out_blocks.append(XOR.fixed(AES.new(key, AES.MODE_ECB).decrypt(in_blocks[i]), in_blocks[i - 1]))

        # Put The Blocks Together And Strip The Padding
        return PKCS7.strip(b"".join(out_blocks), AES128CBC.BLOCK_SIZE)
