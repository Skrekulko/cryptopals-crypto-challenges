#
#   02 - Fixed XOR
#

def fixed_xor(input1: bytes, input2: bytes) -> bytes:
    if len(input1) == len(input2):
        return bytes(a ^ b for (a, b) in zip(input1, input2))
    else:
        raise ValueError

#
#   10 - Implement CBC mode
#

from Crypto.Cipher import AES

class AES128CBC:
    # Class Variables
    block_size = 16
    
    @staticmethod
    def encrypt(input: bytes, key: bytes, iv: bytes) -> bytes:
        padded_input = PKCS7.padding(input, AES128CBC.block_size)
        n_blocks = int(len(padded_input) / AES128CBC.block_size)
        in_blocks = list((padded_input[i * AES128CBC.block_size : i * AES128CBC.block_size + AES128CBC.block_size]) for i in range(n_blocks)) 
        out_blocks = []
        
        # First Block (Using IV)
        out_blocks.append(AES.new(key, AES.MODE_ECB).encrypt(fixed_xor(in_blocks[0], iv)))
        
        for i in range(1, n_blocks):
            out_blocks.append(AES.new(key, AES.MODE_ECB).encrypt(fixed_xor(in_blocks[i], out_blocks[i - 1])))

        return b"".join(out_blocks)
        
    @staticmethod
    def decrypt(input: bytes, key: bytes, iv: bytes) -> bytes:
        n_blocks = int(len(input) / AES128CBC.block_size)
        in_blocks = list((input[i * AES128CBC.block_size : i * AES128CBC.block_size + AES128CBC.block_size]) for i in range(n_blocks))   
        out_blocks = []
        
        # First Block (Using IV)
        out_blocks.append(fixed_xor(AES.new(key, AES.MODE_ECB).decrypt(in_blocks[0]), iv))
        
        for i in range(1, n_blocks):
            out_blocks.append(fixed_xor(AES.new(key, AES.MODE_ECB).decrypt(in_blocks[i]), in_blocks[i - 1]))
        
        return PKCS7.strip(b"".join(out_blocks), AES128CBC.block_size)

#
#   11 - An ECB/CBC detection oracle
#

from random import randint
from os import urandom

class Generator:
    @staticmethod
    def generate_random_bytes(min = 1, max = 16) -> bytes:
        return urandom(randint(min, max))
        
    @staticmethod
    def generate_key_128b() -> bytes:
        return urandom(16)

#
#   15 - PKCS#7 padding validation
#

class PKCS7:
    @staticmethod
    def padding(input: bytes, block_size: int) -> bytes:
        padding_length = block_size - (len(input) % block_size)
        
        if padding_length == block_size:
            return input
        
        return input + padding_length * padding_length.to_bytes(1, "big")
        
    @staticmethod
    def strip(input: bytes, block_size: int) -> bytes:
        last_byte = input[-1]
        
        if last_byte > block_size:
            return input
        
        if input[-last_byte:] != last_byte * last_byte.to_bytes(1, "big"):
            raise ValueError("Incorrect padding.")

        return input[:-last_byte]

#
#   29 - Break a SHA-1 keyed MAC using length extension
#

# The 'Rotate Left' (Circular Left Shift) Operation, ROTL^n(X), Where 'x' Is A 'w-bit' Word And 'n' 
def ROTL(x: int, n: int) -> int:
    return ((x << n) & ((1 << 32) - 1) | (x >> (32 - n)))

# SHA-1 Constants
def SHA1_constants(t: int) -> int:
    # 0 <= t <= 19
    if 0 <= t <= 19:
        return 0x5a827999
    
    # 20 <= t <= 39
    elif 20 <= t <= 39:
        return 0x6ed9eba1
    
    # 40 <= t <= 59
    elif 40 <= t <= 59:
        return 0x8f1bbcdc
    
    # 60 <= t <= 79
    elif 60 <= t <= 79:
        return 0xca62c1d6

# SHA-1 Functions
def SHA1_function(x: int, y: int, z: int, t: int) -> int:
    # Ch(x, y, z) = (x ^ y) + (~x ^ z)               0 <= t <= 19
    if 0 <= t <= 19:
        return ((x & y) ^ (~x & z))
    
    # Parity(x, y, z) = x + y + z                   20 <= t <= 39
    elif 20 <= t <= 39:
        return (x ^ y ^ z)
    
    # Maj(x, y, z) = (x ^ y) + (x ^ z) + (y ^ z)    40 <= t <= 59
    elif 40 <= t <= 59:
        return ((x & y) ^ (x & z) ^ (y & z))
    
    # Parity(x, y, z) = x + y + z                   60 <= t <= 79
    elif 60 <= t <= 79:
        return (x ^ y ^ z)

# SHA-1 Padding      
def SHA1_padding(M: bytes, N = None) -> bytes:
    if N == None:
        N = len(M) * 8                      # Length Of Message In Bits
    else:
        N *= 8
    
    M = (
        M
        + b"\x80"                       # Append '1' ('\x80' -> '1000')
        + b"\x00"                       # Append '0's
        * ((-(N + 1 + 64) % 512) // 8)  # Until 'l + 1 + k ≡ 448 mod 556'
        + N.to_bytes(8, "big")          # Append Message Length
    )
    
    return M

def SHA1(M: bytes, N = None, H = None) -> bytes:
    #
    # Preprocessing
    #
    
    # Padding The Message
    M = SHA1_padding(M, N if N != None else None)
        
    # Parsing The Message
    M = [M[i : i + 64] for i in range(0, len(M), 64)]
    
    # Setting The Initial Hash Value (H(0))
    if H == None:
        H0 = 0x67452301
        H1 = 0xefcdab89
        H2 = 0x98badcfe
        H3 = 0x10325476
        H4 = 0xc3d2e1f0
    else:
        H0 = int.from_bytes(H[0], "big")
        H1 = int.from_bytes(H[1], "big")
        H2 = int.from_bytes(H[2], "big")
        H3 = int.from_bytes(H[3], "big")
        H4 = int.from_bytes(H[4], "big")
    
    #
    # Secure Hash Algorithms
    #
    
    # SHA-1 Hash Computation
    for i in range(len(M)):
        # Prepare The Message Schedule, {'Wt'}
        W = []
        for t in range(80):
            # 0 <= t <= 15
            if 0 <= t <= 15:
                W.append(
                    int.from_bytes(
                        M[i][t * (32 // 8) : t * (32 // 8) + 32 // 8],
                        "big"
                    )
                )
            
            # 16 <= t <= 79
            if 16 <= t <= 79:
                W.append(
                    ROTL(
                        W[t - 3] ^W[t - 8] ^ W[t - 14] ^ W[t - 16],
                        1
                    )
                )
        
        # Initialize The Five Working Variables, 'a', 'b', 'c', 'd', And 'e' with the '(i - 1)^st' Hash Value
        
        a = H0
        b = H1
        c = H2
        d = H3
        e = H4
        
        # For t = 0 to 79
        for t in range(80):
            T = ROTL(a, 5) + SHA1_function(b, c, d, t) + e + SHA1_constants(t) + W[t] & ((1 << 32) - 1)
            e = d
            d = c
            c = ROTL(b, 30)
            b = a
            a = T
            
        # Compute the 'ith' Intermediate Hash Value 'H(t)'
        H0 = (a + H0) & ((1 << 32) - 1)
        H1 = (b + H1) & ((1 << 32) - 1)
        H2 = (c + H2) & ((1 << 32) - 1)
        H3 = (d + H3) & ((1 << 32) - 1)
        H4 = (e + H4) & ((1 << 32) - 1)
    
    return b"".join(H.to_bytes(4, "big") for H in [H0, H1, H2, H3, H4])

#
#   33 - Implement Diffie-Hellman
#

# Modular Exponentiation 'a^b mod m'
def mod_pow(b: int, e: int, m: int) -> int:
    x = 1
    
    while e > 0:
        b, e, x = (
            b * b % m,
            e // 2,
            b * x % m if e % 2 else x
        )
    
    return x
