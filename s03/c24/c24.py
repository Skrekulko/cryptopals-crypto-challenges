#
#   24 - Create the MT19937 stream cipher and break it
#

from helper_c24 import MT19937
from time import time

# Brute-Force The Key Using The Known Plaintext
def mt19937_find_key(ciphertext: bytes, known_text: bytes, MAX_SEED: int) -> int:
    found_key = None
    for i in range(1, MAX_SEED):
        possible_plaintext = mt19937_transform(ciphertext, i)
        if possible_plaintext.endswith(known_text):
            found_key = i
            break
    
    return found_key

# Generate A Token Using The MT19937 Keystream
def generate_token(MAX_SEED: int) -> bytes:
    seed = int(time()) & MAX_SEED
    keystream = mt19937_keystream(seed)
    token = bytes(next(keystream) for _ in range(16))
    
    return token

# Validate The Token (Input) By Brute-Forcing The Possible Keys
def mt19937_validate(token: bytes, MAX_SEED: int) -> bool:
    for i in range(1, MAX_SEED):
        generator = mt19937_keystream(i)
        guess = bytes(next(generator) for _ in range(16))
        if guess == token:
            return True
    else:
        return False

# Generate A Keystream Using MT19937
def mt19937_keystream(key: int):
    if key.bit_length() > 16:
        raise Exception("Not a 16-bit key!")
        
    generator = MT19937(key)
    
    while True:
        random_number = generator.extract_number()
        yield from random_number.to_bytes(4, "big")

# Transform (CTR XOR) The Plaintext Using MT19937 Keystream
def mt19937_transform(plaintext: bytes, key: int):
    keystream = mt19937_keystream(key)
    
    return bytes([x ^ y for (x, y) in zip(plaintext, keystream)])

def c24_find_key(ciphertext: bytes, known_text: bytes, MAX_SEED: int) -> int:
    return mt19937_find_key(ciphertext, known_text, MAX_SEED)

def c24_validate(token: bytes, MAX_SEED: int) -> bool:
    return mt19937_validate(token, MAX_SEED)