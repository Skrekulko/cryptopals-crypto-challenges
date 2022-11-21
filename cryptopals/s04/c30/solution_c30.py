#
#   30 - Break an MD4 keyed MAC using length extension
#

import struct
from cryptopals.oracle import HashOracle
from cryptopals.generator import Generator


class MyOracle(HashOracle):
    def __init__(self) -> None:
        self.key = Generator.random_bytes()
        
    def validate(self, plaintext: bytes, digest: bytes) -> bool:
        return MD4.digest(self.key + plaintext) == digest
        
    def digest(self, plaintext: bytes) -> bytes:
        return MD4.digest(self.key + plaintext)


class MD4:
    # Width Of 32-Bits
    WIDTH = 32

    # 0xFFFFFFFF
    MASK = ((1 << WIDTH) - 1)

    # Number Of Operations
    NO_OPS = 16

    @staticmethod
    def lrot(value, n) -> int:
        lbits, rbits = (value << n) & MD4.MASK, value >> (MD4.WIDTH - n)
        return lbits | rbits

    @staticmethod
    def f_function(x, y, z) -> int:
        return (x & y) | (~x & z)

    @staticmethod
    def g_function(x, y, z) -> int:
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def h_function(x, y, z) -> int:
        return x ^ y ^ z

    @staticmethod
    def padding(plaintext: bytes, plaintext_size=None) -> bytes:
        # Plaintext Size
        plaintext_size = (plaintext_size * 8) if plaintext_size is not None else (len(plaintext) * 8)

        # Pre-Processing
        plaintext = (
                plaintext
                + b"\x80"
                + b"\x00"
                * (-(len(plaintext) + 8 + 1) % 64)
                + struct.pack("<Q", plaintext_size)
        )

        return plaintext

    @staticmethod
    def digest(plaintext=b"", plaintext_size=None, h_registers=None) -> bytes:
        # Registers (Little-Endian)
        h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        if h_registers is not None:
            h = [(struct.unpack("<I", hr)[0]) for hr in h_registers]

        # Pre-Processing
        plaintext = MD4.padding(plaintext, plaintext_size)

        # Process Into 512-Bit Blocks
        for block in [plaintext[i:i + 64] for i in range(0, len(plaintext), 64)]:
            X = struct.unpack("<16I", block)

            # Round 1
            Xi = [3, 7, 11, 19]
            for n in range(MD4.NO_OPS):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h[i] + MD4.f_function(h[j], h[k], h[l]) + X[K]
                h[i] = MD4.lrot(hn & MD4.MASK, S)

            # Round 2
            Xi = [3, 5, 9, 13]
            for n in range(MD4.NO_OPS):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h[i] + MD4.g_function(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.lrot(hn & MD4.MASK, S)

            # Round 3
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(MD4.NO_OPS):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h[i] + MD4.h_function(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.lrot(hn & MD4.MASK, S)

            h = [((v + n) & MD4.MASK) for v, n in zip(h, h)]

        return struct.pack("<4L", *h)


class Decipher:
    @staticmethod
    def md4_length_extension_attack(
            oracle: HashOracle,
            original_mac: bytes,
            original_plaintext: bytes,
            new_plaintext: bytes
    ) -> [bytes, bytes]:
        # Try Different Key Sizes
        for key_size in range(129):
            # Forged Plaintext '(key || original-plaintext || glue-padding || new-plaintext)'
            forged_plaintext = MD4.padding(
                Generator.random_bytes(key_size, key_size) + original_plaintext
            )[key_size:] + new_plaintext

            # Split Digest Into Registers
            h_registers = [original_mac[i * 4:i * 4 + 4] for i in range(len(original_mac) // 4)]

            # Forged MAC Including The New Plaintext With Size Of '(key-size + forged-plaintext-length)'
            forged_mac = MD4.digest(new_plaintext, key_size + len(forged_plaintext), h_registers)

            if oracle.validate(forged_plaintext, forged_mac):
                return forged_plaintext, forged_mac

        # Unable To Guess The Key Size
        raise Exception("Unable to forge the new plaintext!")
