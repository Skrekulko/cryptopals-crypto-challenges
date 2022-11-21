#
#   13 - ECB cut-and-paste
#

from itertools import count
from cryptopals.Oracle import Oracle
from cryptopals.Generator import Generator
from cryptopals.symmetric import AES128ECB
from cryptopals.PKCS import PKCS7
from cryptopals.Solver import Detector
from cryptopals.utils import Blocks
from collections import defaultdict


class MyOracle(Oracle):
    def __init__(self):
        self.key = Generator.key_128b()

    @staticmethod
    def profile_for(email: bytes) -> bytes:
        # Remove Unwanted Characters '&' And '='
        filtered_email = bytes(
            byte for byte in email
            if byte != int.from_bytes(b"&", "big") and byte != int.from_bytes(b"=", "big")
        )

        return b"email=" + filtered_email + b"&uid=10&role=user"

    def encrypt(self, plaintext=b""):
        return AES128ECB.encrypt(self.profile_for(plaintext), self.key)

    def decrypt(self, encrypted_profile):
        return AES128ECB.decrypt(encrypted_profile, self.key)


class MyDetector(Detector):
    @staticmethod
    def block_positions(data: bytes, block_size: int) -> defaultdict[bytes, [int]]:
        # Split The Data Into Blocks
        blocks = Blocks.split_into_blocks(data, block_size)

        # Get Positions Of The Blocks
        positions = defaultdict(list)
        for index, block in enumerate(blocks):
            positions[block].append(index)

        # Return The Blocks With Their Positions
        return positions

    @staticmethod
    def block_size(oracle: Oracle, return_new_block_padding=False) -> [int, int]:
        # Increment The Input Data Size
        for i in count(start=0):
            len1 = len(oracle.encrypt(b"A" * i))
            len2 = len(oracle.encrypt(b"A" * (i + 1)))

            # Difference Found
            if len2 > len1:
                # Return Required Padding Size For New Block
                if return_new_block_padding:
                    return len2 - len1, i
                else:
                    return len2 - len1

    @staticmethod
    def prefix_size(oracle: Oracle, block_size: int) -> int:
        # Find Repeating Blocks With Empty Input
        empty_positions = MyDetector.block_positions(oracle.encrypt(b""), block_size)

        for i in count(start=0):
            # Encrypted Data
            encrypted = oracle.encrypt(
                b"A" * block_size * 2
                + b"A" * i
            )

            # Check The Positions Of The Blocks
            positions = MyDetector.block_positions(encrypted, block_size)

            # Check If Any Repeating Blocks Appeared
            repeated_block, repeated_block_positions = None, None
            for block in positions:
                if block not in empty_positions and len(positions[block]) >= 2:
                    repeated_block = block
                    repeated_block_positions = positions[block]

            # Continue If They Did Not Appear
            if not repeated_block:
                continue

            # Change Bytes Until A Change In The Repeating Blocks Occur
            for j in count(start=1):
                # New Encrypted Data
                encrypted = oracle.encrypt(
                    b"B" * j
                    + b"A" * (block_size * 2 - j)
                    + b"A" * i
                )

                # Get The New Positions
                new_positions = MyDetector.block_positions(encrypted, block_size)

                # One Of The Blocks Got Corrupted
                if not len(new_positions[repeated_block]) >= 2:
                    return block_size * repeated_block_positions[0] - i

            raise Exception("Could not find the prefix size!")

    @staticmethod
    def postfix_size(oracle: Oracle, block_size: int, prefix_size) -> int:
        # Get Empty Input Encrypted Data
        encrypted_empty = oracle.encrypt(b"")

        # Get The Total Amount Of Blocks
        n_blocks_empty = Blocks.number_of_blocks(encrypted_empty, block_size)

        # Increase The Input Size Until New Block Appears
        for i in count(start=1):
            # Count The New Amount Of Blocks
            n_blocks = Blocks.number_of_blocks(
                oracle.encrypt(b"A" * i),
                block_size
            )

            # Difference Found
            if n_blocks != n_blocks_empty:
                return len(encrypted_empty) - (prefix_size + (i - 1))


class Decipher:
    @staticmethod
    def aes_ecb_hijack(oracle: Oracle, message: bytes, postfix_bytes_to_isolate: int) -> bytes:
        # Detect The Block Size
        block_size = Detector.block_size(oracle)

        # Detect Prefix Size
        prefix_size = Detector.prefix_size(oracle, block_size)

        # Calculate Postfix Size
        postfix_size = Detector.postfix_size(oracle, block_size, prefix_size)

        """

        --------------------------------------------------------------------
        | prefix | pr-padding | message | m-padding  | po-padding | postfix |
        --------------------------------------------------------------------

        """

        # Construct Prefix And Message Padding
        prefix_padding_size = block_size - (prefix_size % block_size)
        prefix_padding = b"A" * prefix_padding_size

        message_padding_size = block_size - (len(message) % block_size)

        # Craft The Input
        crafted_message = PKCS7.padding(message, block_size)
        crafted_input = prefix_padding + crafted_message

        # Extract The Encrypted Blocks Containing The Message
        start_block = (prefix_size + prefix_padding_size) // block_size
        end_block = \
            (prefix_size + prefix_padding_size) // block_size \
            + (len(crafted_message) + message_padding_size) // block_size
        encrypted_message_blocks = Blocks.split_into_blocks(
            oracle.encrypt(crafted_input), block_size
        )[start_block:end_block]

        # Construct The Isolation Padding
        isolation_padding_size = block_size - ((prefix_size + postfix_size) % block_size) + postfix_bytes_to_isolate
        isolation_padding = b"A" * isolation_padding_size
        encrypted_isolation_blocks = Blocks.split_into_blocks(
            oracle.encrypt(isolation_padding),
            block_size
        )[:-(postfix_bytes_to_isolate // block_size + 1)]

        # Construct Hijacked Encrypted Data
        hijacked_data = encrypted_isolation_blocks + encrypted_message_blocks

        return b"".join(hijacked_data)
