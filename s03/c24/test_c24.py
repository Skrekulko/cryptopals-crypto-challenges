#
#   24 - Create the MT19937 stream cipher and break it
#

from c24 import c24_find_key, c24_validate, generate_token, mt19937_transform
from helper_c24 import Generator
from random import randint

def test_c24() -> None:
    # Max Seed Value
    MAX_SEED = (1 << 16) - 1
    
    # Randomly Generated Key
    key = randint(1, MAX_SEED)
    
    # Randomly Generated Prefix
    prefix = Generator.generate_random_bytes(2, 20)
    
    # Encrypt The Plaintext
    known_text = b"A" * 14
    plaintext = prefix + known_text
    ciphertext = mt19937_transform(plaintext, key)
    
    # Brute-force The Key
    assert c24_find_key(ciphertext, known_text, MAX_SEED) == key
    
    # Password Reset Token
    token = generate_token(MAX_SEED)
    
    # Validate The Token
    assert c24_validate(token, MAX_SEED) == True
    