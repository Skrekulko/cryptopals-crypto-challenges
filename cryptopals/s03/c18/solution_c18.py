#
#   18 - Implement CTR, the stream cipher mode
#

from cryptopals.utils import Blocks
from cryptopals.XOR import XOR
from cryptopals.symmetric import AES128ECB


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
