#
#   05 - Implement repeating-key XOR
#

from helper_c05 import fixed_xor

def repeating_key_xor(input: bytes, key: bytes) -> bytes:
    repetitions = 1 + (len(input) // len(key))
    key = (key * repetitions)[:len(input)]
    
    return fixed_xor(input, key)

def c05(input, key):
    return repeating_key_xor(input, key)