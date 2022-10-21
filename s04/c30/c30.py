#
#   30 - Break an MD4 keyed MAC using length extension
#

import struct
from helper_c30 import Generator

# MD4
class MD4:
    # Width Of 32-Bits
    width = 32

    # 0xFFFFFFFF
    mask = ((1 << width) - 1)
    
    # Number Of Operations
    no_ops = 16
    
    # Registers (Little-Endian)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    
    def __init__(self, message = None, message_length = None, h_registers = None) -> None:
        # Message
        self.message = message if message != None else b""
        
        # Message Length
        self.message_length = message_length if message_length != None else len(self.message)
        
        # State Registers
        if h_registers != None:
            self.h = [(struct.unpack("<I", hr)[0]) for hr in h_registers]
        
        # Pre-Processing
        message = (
            message
            + b"\x80"
            + b"\x00"
            * (-(self.message_length + 8 + 1) % 64)
            + struct.pack("<Q", self.message_length * 8)
        )
        
        # Process Into 512-Bit Blocks
        self._process([message[i : i + 64] for i in range(0, len(message), 64)])
        
    def _process(self, blocks: [bytes]) -> None:
        for block in blocks:
            X, h = struct.unpack("<16I", block), self.h.copy()
            
            # Round 1
            Xi = [3, 7, 11, 19]
            for n in range(self.no_ops):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h[i] + MD4.F(h[j], h[k], h[l]) + X[K]
                h[i] = MD4.lrot(hn & MD4.mask, S)
                
            # Round 2
            Xi = [3, 5, 9, 13]
            for n in range(self.no_ops):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 3
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(self.no_ops):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.lrot(hn & MD4.mask, S)

            self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]
            
    @staticmethod
    def lrot(value, n) -> int:
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits
    
    @staticmethod
    def F(x, y, z) -> int:
        return (x & y) | (~x & z)
        
    @staticmethod
    def G(x, y, z) -> int:
        return (x & y) | (x & z) | (y & z)
        
    @staticmethod
    def H(x, y, z) -> int:
        return x ^ y ^ z
        
    # Return Digest As A Hexstring
    def digest(self):
        return struct.pack("<4L", *self.h)

class Oracle:
    def __init__(self) -> None:
        self.key = Generator.generate_random_bytes()
        
    def validate(self, message: bytes, digest: bytes) -> bool:
        return MD4(self.key + message).digest() == digest
        
    def get_digest(self, message: bytes) -> bytes:
        return MD4(self.key + message).digest()

def MD4_padding(message: bytes, message_length = None) -> bytes:
    # Message Length
    message_length = (message_length * 8) if message_length != None else (len(message) * 8)

    # Pre-Processing
    message = (
        message
        + b"\x80"
        + b"\x00"
        * (-(len(message) + 8 + 1) % 64)
        + struct.pack("<Q", message_length)
    )
    
    return message

def md4_length_extension_attack(oracle: Oracle, original_mac: bytes, original_message: bytes, new_message: bytes) -> [bytes, bytes]:
    # Try Different Key Sizes
    for key_size in range(129):
        # Forged Message '(original-message || glue-padding || new-message)'
        forged_message = MD4_padding(Generator.generate_random_bytes(key_size, key_size) + original_message)[key_size:] + new_message
        
        # Split Digest Into Registers
        h_registers = [original_mac[i * 4 : i * 4 + 4] for i in range(len(original_mac) // 4)]
        
        # Forged MAC Including The New Message With Size Of '(key-size + forged-message-length)'
        forged_mac = MD4(new_message, key_size + len(forged_message), h_registers).digest()
        
        if oracle.validate(forged_message, forged_mac):
            return forged_message, forged_mac
    
    # Unable To Guess The Key Size
    raise Exception("Unable to forge the new message!")

def c30(oracle: Oracle, original_mac: bytes, original_message: bytes, new_message: bytes) -> [bytes, bytes]:
    return md4_length_extension_attack(oracle, original_mac, original_message, new_message)