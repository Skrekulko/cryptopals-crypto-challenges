#
#   08 - Detect AES in ECB mode
#

from cryptopals.utils import Blocks


class Detector:
    # Block Size Of 16 Bytes (128 Bits)
    BLOCK_SIZE = 16

    @staticmethod
    def repeating_blocks(encrypted_data: bytes) -> bool:
        # Calculate The Total Amount Of Blocks
        n_blocks = Blocks.number_of_blocks(encrypted_data, Detector.BLOCK_SIZE)

        # Parse Into Blocks (Without Duplicates)
        blocks = list(dict.fromkeys(Blocks.split_into_blocks(encrypted_data, Detector.BLOCK_SIZE, n_blocks)))

        # Compare The Number Of Non-Repeating Blocks With Total Amount Of Blocks
        if len(blocks) != n_blocks:
            return True
        else:
            return False
