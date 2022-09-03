#
#   06 - Break repeating-key XOR
#

import codecs
from helper_c06 import single_byte_xor_decipher, repeating_key_xor

def convert_base64_to_hex(input: bytes) -> bytes:
    return codecs.encode(codecs.decode(input, "base64"), "hex")
    
def hamming_distance(input1: bytes, input2: bytes) -> int:
    distance = 0
    
    for byte1, byte2 in zip(input1, input2):
        distance += bin(byte1 ^ byte2).count("1")
        
    return distance
    
def hamming_score(input1: bytes, input2: bytes) -> float:
    return hamming_distance(input1, input2) / (8 * min(len(input1), len(input2)))

def compute_key_length(input: bytes) -> int:
    min_score, key_len = None, None
    
    #for klen in range(2, math.ceil(len(input) / 2)):
    for klen in range(2, 40):
        chunks = [
            input[i: i + klen]
            for i in range(0, len(input), klen)
        ]
        
        if len(chunks) >= 2 and len(chunks[-1]) <= len(chunks[-2]) / 2:
            chunks.pop()
            
        _scores = []
        for i in range(0, len(chunks) - 1, 1):
            for j in range(i + 1, len(chunks), 1):
                score = hamming_score(chunks[i], chunks[j])
                _scores.append(score)
                
                
        if len(_scores) == 0:
            continue
            
        score = sum(_scores) / len(_scores)
        
        if min_score is None or score < min_score:
            min_score, key_len = score, klen
            
    return key_len

def load_data(file_name: str) -> bytes:
    with open(file_name) as file:
        data = file.read()
        data = codecs.decode(bytes(data.encode("ascii")), "base64")
        return data

def decipher_repeating_xor(data: bytes) -> tuple[bytes, bytes]:
    key_len = compute_key_length(data)
    
    chunks = list((data[i::key_len]) for i in range(key_len))
    
    deciphered = b""
    key = b""
    for chunk in chunks:
        key += (single_byte_xor_decipher(chunk)[1].to_bytes(1, "big"))
        
    xored = repeating_key_xor(data, key)
    
    return xored, key

def c06(file_name):
    return decipher_repeating_xor(load_data(file_name))