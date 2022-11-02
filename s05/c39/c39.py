#
#   39 - Implement RSA
#

from Crypto.Util.number import getPrime

# Greatest Common Divider
def gcd(a: int, b: int) -> int:
    return gcd(b, a % b) if b else abs(a)

# Least Common Multiple
def lcm(a: int, b: int) -> int:
    return abs(a * b) // gcd(a, b) if a and b else 0

# Modular Inverse
def mod_inv(a: int, n: int) -> int:
    t, r = 0, n
    new_t, new_r = 1, a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("'a' does not have a modular inverse!")
    
    if t < 0:
        t = t + n

    return t

# Convert An Integer To Bytes
def int_to_bytes(integer: int) -> bytes:
    integer_len = (max(integer.bit_length(), 1) + 7) // 8
    integer_bytes = integer.to_bytes(integer_len, "big")
    
    return integer_bytes

class RSA:
    def __init__(self, key_len: int, e = 3):
        # Public Exponent 'e'
        self.e = e
        
        phi = 0
        while gcd(self.e, phi) != 1:
            # Secret Primes 'p' And 'q' (q < p)
            p, q = getPrime(key_len // 2), getPrime(key_len // 2)
            
            phi = lcm(p - 1, q - 1)
            
            # Public Modulus 'n'
            self.n = p * q
        
        # Secret Exponent 'd'
        self._d = mod_inv(self.e, phi)
        
    def encrypt(self, input: bytes) -> bytes:
        return int_to_bytes(
            pow(
                int.from_bytes(input, "big"),
                self.e,
                self.n
            )
        )
        
    def decrypt(self, input: bytes) -> bytes:
        return int_to_bytes(
            pow(
                int.from_bytes(input, "big"),
                self._d,
                self.n
            )
        )

def c39(key_len: int, e: int, plaintext: bytes) -> None:
    return RSA(key_len, e).encrypt(plaintext)
