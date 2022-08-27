#!/usr/bin/python3

import codecs
from collections import Counter
from Crypto.Cipher import AES
from random import randint
from os import urandom
from itertools import count

#
#   01 - Convert hex to base64
#

def convert_hex_to_base64(input: bytes) -> bytes:
    return codecs.encode(codecs.decode(input, "hex"), "base64").rstrip()

#
#   02 - Fixed XOR
#

def fixed_xor(input1: bytes, input2: bytes) -> bytes:
    if len(input1) == len(input2):
        return bytes(a ^ b for (a, b) in zip(input1, input2))
    else:
        raise ValueError

#
#   03 - Single-byte XOR cipher
#
occurance_english = {
    'a': 8.2389258,    'b': 1.5051398,
    'c': 2.8065007,    'd': 4.2904556,
    'e': 12.813865,    'f': 2.2476217,
    'g': 2.0327458,    'h': 6.1476691,
    'i': 6.1476691,    'j': 0.1543474,
    'k': 0.7787989,    'l': 4.0604477,
    'm': 2.4271893,    'n': 6.8084376,
    'o': 7.5731132,    'p': 1.9459884,
    'q': 0.0958366,    'r': 6.0397268,
    's': 6.3827211,    't': 9.1357551,
    'u': 2.7822893,    'v': 0.9866131,
    'w': 2.3807842,    'x': 0.1513210,
    'y': 1.9913847,    'z': 0.0746517
}

dist_english = list(occurance_english.values())

def single_byte_xor(input: bytes, key: int) -> bytes:
    return bytes((byte ^ key) for byte in input)

def compute_fitting_quotient(text: bytes) -> float:
    counter = Counter(text)
    dist_text = [
        (counter.get(ord(ch), 0) * 100) / len(text)
        for ch in occurance_english
    ]
    
    return sum([abs(a - b) for a, b in zip(dist_english, dist_text)]) / len(dist_text)

def single_byte_xor_decipher(input: bytes) -> tuple[bytes, int, float]:
    original_text, encryption_key, min_fq = None, None, None
    
    for k in range(256):
        _input = single_byte_xor(input, k)
        _freq = compute_fitting_quotient(_input)

        if min_fq is None or _freq < min_fq:
            encryption_key, original_text, min_fq = k, _input, _freq

    return original_text, encryption_key, min_fq
    
#
#   04 - Detect single-character XOR
#

def load_ciphers(file_name: str) -> list[bytes]:
    with open(file_name) as file:
        return (bytes.fromhex(line.rstrip()) for line in file.readlines())

def detect_single_character_xor(ciphers: list) -> tuple[bytes, int, float]:
    deciphered = (single_byte_xor_decipher(cipher) for cipher in ciphers)
    
    return min(deciphered, key = lambda t: t[2])

#
#   05 - Implement repeating-key XOR
#

def repeating_key_xor(input: bytes, key: bytes) -> bytes:
    repetitions = 1 + (len(input) // len(key))
    key = (key * repetitions)[:len(input)]
    
    return fixed_xor(input, key)

#
#   06 - Break repeating-key XOR
#

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

#
#   07 - AES in ECB mode
#

def decrypt_aes_ecb(input: bytes, key: bytes) -> bytes:
    blocks = list((input[i * 16 : i * 16 + 16]) for i in range(16))
    
    decrypted = b""
    for block in blocks:
        cipher_block = AES.new(key, AES.MODE_ECB)
        decrypted += cipher_block.decrypt(block)

    return pkcs7_unpadding(decrypted)
    
#
#   08 - Detect AES in ECB mode
#

def detect_repeated_blocks(input: bytes, block_size: int) -> bool:
    n_blocks = int(len(input) / block_size)
    blocks = list((input[i * block_size : i * block_size + block_size]) for i in range(n_blocks))
    
    if len(set(blocks)) != n_blocks:
        return True
    else:
        return False
        
#
#   09 - Implement PKCS#7 padding
#

def pkcs7_padding(input: bytes, block_size: int) -> bytes:
    len_input = len(input)
    len_padding = block_size - (len_input % block_size)
    
    if len_padding == block_size:
        return input
    
    padding = len_padding * len_padding.to_bytes(1, "big")
    
    padded_input = input + padding
    
    return padded_input

def pkcs7_unpadding(input: bytes) -> bytes:
    last_byte = input[-1]
    if input[-last_byte:] == last_byte * last_byte.to_bytes(1, "big"):
        return input[:-last_byte]
    else:
        return input

#
#   10 - Implement CBC mode
#

def encrypt_aes_ecb_block(block: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(block)

def decrypt_aes_ecb_block(block: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(block)

def decrypt_aes_cbc(input: bytes, key: bytes, iv: bytes) -> bytes:
    n_blocks = int(len(input) / 16)
    in_blocks = list((input[i * 16 : i * 16 + 16]) for i in range(n_blocks)) 
    
    decrypted = fixed_xor(decrypt_aes_ecb_block(in_blocks[0], key), iv)
    
    for i in range(1, n_blocks):
       decrypted += fixed_xor(decrypt_aes_ecb_block(in_blocks[i], key), in_blocks[i - 1])
        
    return pkcs7_unpadding(decrypted)

#
#   11 - An ECB/CBC detection oracle
#

def generate_key_128b() -> bytes:
    return bytes(randint(0 , 15) for i in range(16))

def encrypt_aes_ecb(input: bytes, key: bytes) -> bytes:
    padded_input = pkcs7_padding(input, 16)
    n_blocks = int(len(padded_input) / 16)
    blocks = list((padded_input[i * 16 : i * 16 + 16]) for i in range(n_blocks))
    
    encrypted = b""
    for block in blocks:
        cipher_block = AES.new(key, AES.MODE_ECB)
        encrypted += cipher_block.encrypt(block)

    return encrypted

def encrypt_aes_cbc(input: bytes, key: bytes, iv: bytes) -> bytes:
    padded_input = pkcs7_padding(input, 16)
    n_blocks = int(len(padded_input) / 16)
    in_blocks = list((padded_input[i * 16 : i * 16 + 16]) for i in range(n_blocks)) 
    
    encrypted = encrypt_aes_ecb_block(fixed_xor(in_blocks[0], iv), key)
    for i in range(1, n_blocks):
       encrypted += encrypt_aes_ecb_block(fixed_xor(in_blocks[i], in_blocks[i - 1]), key)
        
    return encrypted

def encrypt_oracle(input: bytes) -> bytes:
    key = generate_key_128b()
    header = urandom(randint(5, 10))
    footer = urandom(randint(5, 10))
    full_input = header + input + footer
    
    if randint(0, 1):
        return ("ecb", encrypt_aes_ecb(full_input, key))
    else:
        return ("cbc", encrypt_aes_cbc(full_input, key, generate_key_128b()))
        
def detect_aes_ecb_or_cbc(cipher: bytes) -> tuple[str, bytes]:
    cipher_len = len(cipher)
    n_blocks = cipher_len // 16
    chunks = Counter((cipher[i * 16 : i * 16 + 16]) for i in range(n_blocks))
    
    return ("ecb", max(chunks)) if len(chunks) != n_blocks else ("cbc", list(chunks.elements())[0])

#
#   12 - Byte-at-a-time ECB decryption (Simple)
#

def encrypt_oracle_ecb(unknown_input: bytes, to_append: bytes, key: bytes) -> bytes:
    return encrypt_aes_ecb(unknown_input + to_append, key)

def byte_at_a_time_ecb_decryption(input: bytes) -> bytes:
    unknown_input = codecs.decode(input, "base64")
    key = generate_key_128b()
    
    # Detect Block Size
    block_size = 0
    unknown_input_len = 0
    for i in count(start = 0):
        encrypted1 = encrypt_oracle_ecb(b"A" * i, unknown_input, key)
        encrypted2 = encrypt_oracle_ecb(b"A" * (i + 1), unknown_input, key)
        encrypted1_len = len(encrypted1)
        encrypted2_len = len(encrypted2)
        
        if encrypted2_len > encrypted1_len:
            block_size = encrypted2_len - encrypted1_len
            unknown_input_len = encrypted1_len - i
            break
    
    # Detect Encryption Mode
    detected_mode = detect_aes_ecb_or_cbc(encrypt_oracle_ecb(b"A" * block_size * 2, unknown_input, key))
    
    # Extract The Unknown Input
    decrypted = b""
    for _ in range(unknown_input_len):
        # Craft The Needed Padding
        decrypted_len = len(decrypted)
        padding_len = (- decrypted_len - 1) % block_size
        padding = b"A" * padding_len
        
        # Calculate And Get The Target Block
        target_block_number = decrypted_len // block_size
        target_slice = slice(target_block_number * block_size, (target_block_number + 1) * block_size)
        target_block = encrypt_oracle_ecb(padding, unknown_input, key)[target_slice]
        
        # Brute-Force All Possible Combinations For A Single Byte
        for byte in range(256):
            crafted_input = padding + decrypted + byte.to_bytes(1, "big")
            crafted_block = encrypt_oracle_ecb(crafted_input, unknown_input, key)[target_slice]
            
            # Match Found
            if crafted_block == target_block:
                decrypted += byte.to_bytes(1, "little")
                break
                
    return decrypted

#
#   13 - ECB cut-and-paste
#

class Profile:
    def __init__(self):
        self.key = generate_key_128b()
        
    @staticmethod
    def profile_for(email: bytes) -> bytes:
        # Remove Unwated Characters '&' And '='
        filtered_email = bytes(byte for byte in email if byte != int.from_bytes(b"&", "big") and byte != int.from_bytes(b"=", "big"))
        return b"email=" + filtered_email + b"&uid=10&role=user"
        
    def encrypt_profile(self, email):
        return encrypt_aes_ecb(self.profile_for(email), self.key)
        
    def decrypt_profile(self, encrypted_profile):
        return decrypt_aes_ecb(encrypted_profile, self.key)
    
def hijack_user_role() -> bytes:
    # Create Profile Manager
    manager = Profile()
    
    # Detect Block Size
    block_size = 0
    for i in count(start = 0):
        encrypted1 = manager.encrypt_profile(b"A" * i)
        encrypted2 = manager.encrypt_profile(b"A" * (i + 1))
        encrypted1_len = len(encrypted1)
        encrypted2_len = len(encrypted2)
        
        if encrypted2_len > encrypted1_len:
            block_size = encrypted2_len - encrypted1_len
            break
    
    # Automated Attack
    target_block = b""
    for i in count(start = 0):
        crafted_role = pkcs7_padding(b"admin", block_size)
        crafted_email = i * b"A" + crafted_role
        profile = manager.profile_for(crafted_email)
        padded_profile = pkcs7_padding(profile, block_size)
        padded_profile_blocks = list(profile[i * block_size : i * block_size + block_size] for i in range(len(padded_profile) // block_size))

        try:
            index = padded_profile_blocks.index(crafted_role)
            encrypted = manager.encrypt_profile(crafted_email)
            target_block = encrypted[index * block_size : (index + 1) * block_size]
            break
        except ValueError:
            continue
        
    for i in count(start = 0):
        crafted_email = i * b"A"
        profile = manager.profile_for(crafted_email)
        padded_profile = pkcs7_padding(profile, block_size)
        padded_profile_blocks = list(profile[i * block_size : i * block_size + block_size] for i in range(len(padded_profile) // block_size))

        if b"user" in padded_profile_blocks:
            encrypted = manager.encrypt_profile(crafted_email)
            hijacked_encrypted = encrypted[:-block_size] + target_block
            decrypted = manager.decrypt_profile(hijacked_encrypted)
            break

    return decrypted

def main():
    print("The Crytopals Crypto Challenges")

if __name__ == "__main__":
    main()