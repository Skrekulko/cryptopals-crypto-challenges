import struct
from cryptopals.XOR import XOR


class SHA1:
    @staticmethod
    def rotl(x: int, n: int) -> int:
        return (x << n) & ((1 << 32) - 1) | (x >> (32 - n))

    @staticmethod
    def constants(t: int) -> int:
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

    @staticmethod
    def functions(x: int, y: int, z: int, t: int) -> int:
        # Ch(x, y, z) = (x ^ y) + (~x ^ z)               0 <= t <= 19
        if 0 <= t <= 19:
            return (x & y) ^ (~x & z)

        # Parity(x, y, z) = x + y + z                   20 <= t <= 39
        elif 20 <= t <= 39:
            return x ^ y ^ z

        # Maj(x, y, z) = (x ^ y) + (x ^ z) + (y ^ z)    40 <= t <= 59
        elif 40 <= t <= 59:
            return (x & y) ^ (x & z) ^ (y & z)

        # Parity(x, y, z) = x + y + z                   60 <= t <= 79
        elif 60 <= t <= 79:
            return x ^ y ^ z

    @staticmethod
    def padding(m: bytes, n=None) -> bytes:
        if n is None:
            n = len(m) * 8  # Length Of Message In Bits
        else:
            n *= 8

        M = (
                m
                + b"\x80"  # Append '1' ('\x80' -> '1000')
                + b"\x00"  # Append '0's
                * ((-(n + 1 + 64) % 512) // 8)  # Until 'l + 1 + k ≡ 448 mod 556'
                + n.to_bytes(8, "big")  # Append Message Length
        )

        return M

    @staticmethod
    def digest(m: bytes, n=None, h=None) -> bytes:
        #
        # Preprocessing
        #

        # Padding The Message
        m = SHA1.padding(m, n if n is not None else None)

        # Parsing The Message
        m = [m[i: i + 64] for i in range(0, len(m), 64)]

        # Setting The Initial Hash Value (H(0))
        if h is None:
            H0 = 0x67452301
            H1 = 0xefcdab89
            H2 = 0x98badcfe
            H3 = 0x10325476
            H4 = 0xc3d2e1f0
        else:
            H0 = int.from_bytes(h[0], "big")
            H1 = int.from_bytes(h[1], "big")
            H2 = int.from_bytes(h[2], "big")
            H3 = int.from_bytes(h[3], "big")
            H4 = int.from_bytes(h[4], "big")

        #
        # Secure Hash Algorithms
        #

        # SHA-1 Hash Computation
        for i in range(len(m)):
            # Prepare The Message Schedule, {'Wt'}
            W = []
            for t in range(80):
                # 0 <= t <= 15
                if 0 <= t <= 15:
                    W.append(
                        int.from_bytes(
                            m[i][t * (32 // 8): t * (32 // 8) + 32 // 8],
                            "big"
                        )
                    )

                # 16 <= t <= 79
                if 16 <= t <= 79:
                    W.append(
                        SHA1.rotl(
                            W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16],
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
                T = SHA1.rotl(a, 5) + SHA1.functions(b, c, d, t) + e + SHA1.constants(t) + W[t] & ((1 << 32) - 1)
                e = d
                d = c
                c = SHA1.rotl(b, 30)
                b = a
                a = T

            # Compute the 'ith' Intermediate Hash Value 'H(t)'
            H0 = (a + H0) & ((1 << 32) - 1)
            H1 = (b + H1) & ((1 << 32) - 1)
            H2 = (c + H2) & ((1 << 32) - 1)
            H3 = (d + H3) & ((1 << 32) - 1)
            H4 = (e + H4) & ((1 << 32) - 1)

        return b"".join(H.to_bytes(4, "big") for H in [H0, H1, H2, H3, H4])

    @staticmethod
    def hmac(k: bytes, text: bytes) -> bytes:
        # SHA-1 Block Size
        B = 64

        # Key Length
        K_len = len(k)

        # ipad, opad
        ipad, opad = b"\x36" * B, b"\x5c" * B

        if K_len == B:
            K0 = k
        else:
            if K_len > B:
                L = SHA1.digest(k)
                L_len = len(L)
                # K0 = H(K) || (B - L) * 00 .. 00
                K0 = L + (B - L_len) * b"\x00"
            else:
                # K0 = (B - K) * 00 .. 00
                K0 = k + (B - K_len) * b"\x00"

        # 'H((K0 + opad) || H((K0 + ipad) || text))'
        return SHA1.digest(XOR.fixed(K0, opad) + SHA1.digest(XOR.fixed(K0, ipad) + text))


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
