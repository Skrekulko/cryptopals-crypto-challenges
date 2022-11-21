from Crypto.Cipher import AES
from cryptopals.PKCS import PKCS7
from cryptopals.XOR import XOR
from cryptopals.utils import Blocks


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


class AES128CTR:
    # Block Size Of 16 Bytes (128 Bits)
    BLOCK_SIZE = 16

    @staticmethod
    def transform(text: bytes, key: bytes, nonce: int) -> bytes:
        # Counter
        counter = 0

        # Parse The Text (Plaintext/Ciphertext) Into Blocks
        text_blocks = Blocks.split_into_blocks(text, AES128CTR.BLOCK_SIZE, keep_non_multiple=True)

        # Ciphertext Blocks
        ciphertext_blocks = []

        # Transform Each Block
        for text_block in text_blocks:
            # Construct A Keystream Block
            keystream_block = (
                    nonce.to_bytes(AES128CTR.BLOCK_SIZE // 2, "little")
                    +
                    counter.to_bytes(AES128CTR.BLOCK_SIZE // 2, "little")
            )
            encrypted_block = AES128ECB.encrypt(keystream_block, key)

            # XOR The Keystream Block With The Input Block
            ciphertext_block = XOR.repeating(text_block, encrypted_block)
            ciphertext_blocks.append(ciphertext_block)

            # Increment The Counter
            counter += 1

        return b"".join(ciphertext_blocks)
