#
#   02 - Fixed XOR
#

def fixed_xor(input1: bytes, input2: bytes) -> bytes:
    if len(input1) == len(input2):
        return bytes(a ^ b for (a, b) in zip(input1, input2))
    else:
        raise ValueError

#
#   05 - Implement repeating-key XOR
#

def repeating_key_xor(input: bytes, key: bytes) -> bytes:
    repetitions = 1 + (len(input) // len(key))
    key = (key * repetitions)[:len(input)]
    
    return fixed_xor(input, key)
