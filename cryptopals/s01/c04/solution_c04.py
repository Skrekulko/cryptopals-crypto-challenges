#
#   04 - Detect single-character XOR
#

from cryptopals.solver import Decipher


def load_lines(file_name: str) -> list[bytes]:
    with open(file_name) as file:
        return [bytes.fromhex(line.rstrip()) for line in file.readlines()]


class Detector:
    @staticmethod
    def single_character_xor(ciphertexts: list) -> tuple[bytes, int, float]:
        # Decipher Every Ciphertext Line
        plaintext = [Decipher.single_byte_xor(ciphertext) for ciphertext in ciphertexts]

        # Return The Plaintext Line And The Secret Key
        return min(plaintext, key=lambda t: t[2])
