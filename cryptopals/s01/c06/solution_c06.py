#
#   06 - Break repeating-key XOR
#

import codecs
from cryptopals.XOR import XOR
from cryptopals.Solver import Frequency


class Converter:
    @staticmethod
    def base64_to_hex(base64_bytes: bytes) -> bytes:
        return codecs.decode(base64_bytes, "base64")

    @staticmethod
    def int_to_hex(integer: int) -> bytes:
        integer_len = (max(integer.bit_length(), 1) + 7) // 8
        integer_bytes = integer.to_bytes(integer_len, "big")

        return integer_bytes


class Hamming:
    @staticmethod
    def distance(byte_string1: bytes, byte_string2: bytes) -> int:
        # Initial Distance
        distance = 0

        # Compare Each Byte And Calculate The Total Distance
        for byte1, byte2 in zip(byte_string1, byte_string2):
            distance += bin(byte1 ^ byte2).count("1")

        return distance

    @staticmethod
    def score(input1: bytes, input2: bytes) -> float:
        # Calculate The Hamming Score (Total Distance Divided By The Minimal Length)
        return Hamming.distance(input1, input2) / (8 * min(len(input1), len(input2)))

    @staticmethod
    def compute_key_length(encrypted_data: bytes) -> int:
        min_score, key_len = None, None

        # For Quick Finding, The Top Is Capped At 40, But Correctly It Should Be Capped
        # At 'math.ceil(len(input) / 2)' (Might Also Result In Weird Or Wrong Answers)
        for klen in range(2, 40):
            # Process The Input Into Chunks Of 'klen' Size
            chunks = [
                encrypted_data[i: i + klen]
                for i in range(0, len(encrypted_data), klen)
            ]

            if len(chunks) >= 2 and len(chunks[-1]) <= len(chunks[-2]) / 2:
                chunks.pop()

            # Calculate The Different Scores
            _scores = []
            for i in range(0, len(chunks) - 1, 1):
                for j in range(i + 1, len(chunks), 1):
                    score = Hamming.score(chunks[i], chunks[j])
                    _scores.append(score)

            # Start The Next Loop If We've Got No Scores
            if len(_scores) == 0:
                continue

            # Total Score
            score = sum(_scores) / len(_scores)

            # Check If We've Got A Better Score
            if min_score is None or score < min_score:
                min_score, key_len = score, klen

        return key_len


class Decipher:
    @staticmethod
    def single_byte_xor(encrypted_bytes: bytes) -> tuple[bytes, int, float]:
        original_text, encryption_key, min_fq = None, None, None

        for k in range(256):
            _input = XOR.single_byte(encrypted_bytes, k)
            _freq = Frequency.compute_fitting_quotient(_input)

            if min_fq is None or _freq < min_fq:
                encryption_key, original_text, min_fq = k, _input, _freq

        return original_text, encryption_key, min_fq

    @staticmethod
    def repeating_xor(data: bytes) -> tuple[bytes, bytes]:
        # Get The (Possible) Key Size
        key_len = Hamming.compute_key_length(data)

        # Split The Input Into Chunks
        chunks = list((data[i::key_len]) for i in range(key_len))

        # Get The Secret Key
        key = b"".join(Converter.int_to_hex(Decipher.single_byte_xor(chunk)[1]) for chunk in chunks)

        # Get The Decrypted Data By XORing The Encrypted Data With The Secret Key
        xored = XOR.repeating(data, key)

        return xored, key


def load_data(file_name: str) -> bytes:
    with open(file_name) as file:
        data = file.read()
        data = codecs.decode(bytes(data.encode("ascii")), "base64")
        return data
