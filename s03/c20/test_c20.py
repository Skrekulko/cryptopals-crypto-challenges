#
#   20 - Break fixed-nonce CTR statistically
#

from c20 import c20
from helper_c20 import Generator, AES128CTR
import codecs
from difflib import SequenceMatcher

def test_c20() -> None:
    # Load Strings From File
    file_name = "20.txt"
    strings = []
    with open(file_name) as file:
        strings = [
            codecs.decode(
                bytes(line.rstrip().encode("ascii")),
                "base64"
            ) for line in file.readlines()
        ]
    
    # Randomly Generated Key
    key = Generator.generate_key_128b()
    
    # Nonce
    nonce = 0
    
    # Initialize New AES CTR
    ctr = AES128CTR(key, nonce)
    
    # Transform Strings Into Ciphertexts
    ciphertexts = [
        ctr.transform(
            string
        ) for string in strings
    ]
    
    # Decrypt The Strings
    plaintexts = c20(ciphertexts, key, nonce)
    
    # Minimal Ratio To Get A Point
    minimum_ratio = 0.75
    
    # Minimal Number Of Points To Pass The Test
    minimum_score = len(strings) / 2
    
    # Actual Score
    score = 0
    for (string, plaintext) in zip(strings, plaintexts):
        print(string)
        print(plaintext)
        if SequenceMatcher(None, string, plaintext).ratio() > minimum_ratio:
            score += 1
    
    assert score >= minimum_score
