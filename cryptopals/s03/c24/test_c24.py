#
#   24 - Create the MT19937 stream cipher and break it
#

from cryptopals.s03.c24.solution_c24 import StaticMT19937, Decipher, mt19937_validate, generate_token
from random import randint
from cryptopals.Generator import Generator


def test_c24() -> None:
    # Max Seed Value ( For Time Saving, A Small Value Is Used)
    # MAX_SEED = (1 << 16) - 1
    MAX_SEED = (1 << 8) - 1

    # Randomly Generated Secret Key
    key = randint(1, MAX_SEED)
    
    # Randomly Generated Prefix
    prefix = Generator.random_bytes(2, 20)
    
    # Encrypt The Plaintext
    plaintext = b"A" * 14
    padded_plaintext = prefix + plaintext
    ciphertext = StaticMT19937.transform(padded_plaintext, key)
    
    # Brute-force The Key
    assert Decipher.mt19937_find_key(ciphertext, padded_plaintext, MAX_SEED) == key
    
    # Password Reset Token
    token = generate_token(MAX_SEED)
    
    # Validate The Token
    assert mt19937_validate(token, MAX_SEED)
    