#
#   20 - Break fixed-nonce CTR statistically
#

from difflib import SequenceMatcher
from cryptopals.Generator import Generator
from cryptopals.converter import Converter
from cryptopals.symmetric import AES128CTR
from cryptopals.Solver import Decipher


def test_c20() -> None:
    # File Name
    file_name = "20.txt"

    # Decode The Base64 Encoded Strings Into Byte String
    with open(file_name) as file:
        plaintext_strings = [Converter.base64_to_hex(line.rstrip().encode()) for line in file.readlines()]

    # Secret Key
    key = Generator.key_128b()

    # Secret Nonce
    nonce = 0

    # Transform The Plaintext Strings Into Ciphertexts
    ciphertext_strings = [AES128CTR.transform(plaintext_string, key, nonce) for plaintext_string in plaintext_strings]

    # Decrypt The Ciphertext Strings
    decrypted_strings = Decipher.aes_ctr_fixed_nonce(ciphertext_strings)

    # Minimal Ratio To Get A Point
    minimum_ratio = 0.90

    # Minimal Number Of Points To Pass The Test
    minimum_score = len(plaintext_strings) / 2

    # Actual Score
    score = 0

    # Start Scoring
    for (plaintext_string, decrypted_string) in zip(plaintext_strings, decrypted_strings):
        if SequenceMatcher(None, plaintext_string, decrypted_string).ratio() > minimum_ratio:
            score += 1

    assert score >= minimum_score
