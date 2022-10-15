#
#   28 - Implement a SHA-1 keyed MAC
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

def SHA1(M: bytes) -> bytes:
    #
    # Preprocessing
    #
    
    # Padding the Message
    l = len(M) * 8                      # Length Of Message In Bits
    M += b"\x80"                        # Append '1' ('\x80' -> '1000')
    while (len(M) * 8) % 512 != 448:    # Append '0's Until 'l + 1 + k ≡ 448 mod 556'
        M += b"\x00"
    M += l.to_bytes(8, "big")           # Append Message Length
    
    # Parsing The Message
    M = [M[i : i + 512] for i in range(0, len(M), 512)]
    N = len(M)
    
    # Setting The Initial Hash Value (H(0))
    H0 = 0x67452301
    H0 = 0x67452301
    H1 = 0xefcdab89
    H2 = 0x98badcfe
    H3 = 0x10325476
    H4 = 0xc3d2e1f0
    
    #
    # Secure Hash Algorithms
    #
    
    # SHA-1 Hash Computation
    for i in range(N):
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
        
    return bytes.fromhex("%08x%08x%08x%08x%08x" % (H0, H1, H2, H3, H4))