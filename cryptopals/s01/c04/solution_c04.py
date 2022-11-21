#
#   04 - Detect single-character XOR
#

from cryptopals.Solver import Decipher


def load_lines(file_name: str) -> list[bytes]:
    with open(file_name) as file:
        return [bytes.fromhex(line.rstrip()) for line in file.readlines()]


class Detector:
    @staticmethod
    def single_character_xor(ciphers: list) -> tuple[bytes, int, float]:
        # Decipher Every Encrypted Line And Put Them Together
        deciphered = [Decipher.single_byte_xor(cipher) for cipher in ciphers]

        # Return The Deciphered Data And The Secret Key
        return min(deciphered, key=lambda t: t[2])
