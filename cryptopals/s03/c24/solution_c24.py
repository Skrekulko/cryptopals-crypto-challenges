#
#   24 - Create the MT19937 stream cipher and break it
#

from time import time
from cryptopals.Generator import MT19937


class StaticMT19937:
    @staticmethod
    def keystream(key: int):
        if key.bit_length() > 16:
            raise Exception("Not a 16-bit key!")

        generator = MT19937(key)

        while True:
            random_number = generator.extract_number()
            yield from random_number.to_bytes(4, "big")

    @staticmethod
    def transform(plaintext: bytes, key: int):
        return bytes([x ^ y for (x, y) in zip(plaintext, StaticMT19937.keystream(key))])


class Decipher:
    @staticmethod
    def mt19937_find_key(ciphertext: bytes, known_text: bytes, max_seed: int) -> int:
        found_key = None
        for i in range(1, max_seed):
            possible_plaintext = StaticMT19937.transform(ciphertext, i)
            if possible_plaintext.endswith(known_text):
                found_key = i
                break

        return found_key


# Validate The Token (Input) By Brute-Forcing The Possible Keys
# noinspection PyTypeChecker
def mt19937_validate(token: bytes, max_seed: int) -> bool:
    for i in range(1, max_seed):
        generator = StaticMT19937.keystream(i)
        guess = bytes([next(generator) for _ in range(16)])
        print(guess)
        if guess == token:
            return True
    else:
        return False


# Generate A Token Using The MT19937 Keystream
# noinspection PyTypeChecker
def generate_token(max_seed: int) -> bytes:
    seed = int(time()) & max_seed
    keystream = StaticMT19937.keystream(seed)
    token = bytes([next(keystream) for _ in range(16)])

    return token
