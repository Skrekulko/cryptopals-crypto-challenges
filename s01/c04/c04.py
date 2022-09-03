#
#   04 - Detect single-character XOR
#

from collections import Counter
from helper_c04 import single_byte_xor_decipher

def load_ciphers(file_name: str) -> list[bytes]:
    with open(file_name) as file:
        return (bytes.fromhex(line.rstrip()) for line in file.readlines())

def detect_single_character_xor(ciphers: list) -> tuple[bytes, int, float]:
    deciphered = (single_byte_xor_decipher(cipher) for cipher in ciphers)
    
    return min(deciphered, key = lambda t: t[2])

def c04(file_name):
    return detect_single_character_xor(load_ciphers(file_name))