#
#   40 - Implement an E=3 RSA Broadcast attack
#

from Crypto.Util.number import getPrime
from functools import reduce

# Greatest Common Divider
def gcd(a: int, b: int) -> int:
    return gcd(b, a % b) if b else abs(a)

# Least Common Multiple
def lcm(a: int, b: int) -> int:
    return abs(a * b) // gcd(a, b) if a and b else 0

# Extended GCD
def extended_gcd(aa: int, bb: int) -> int:
    lastremainder, remainder = abs(aa), abs(bb)
    
    x, lastx, y, lasty = 0, 1, 1, 0
    
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
        
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

# Modular Inverse
def mod_inv(a: int, m: int) -> int:
	g, x, y = extended_gcd(a, m)
    
	if g != 1:
		raise ValueError
    
	return x % m

# Integer Root 'Nth' Of 'X'
def root(a: int, b: int) -> int:
    # Root Is Less Than 2 (Root Is 1)
    if b < 2:
        return b
    
    a1 = a - 1
    c = 1
    d = (a1 * c + b // (c ** a1)) // a
    e = (a1 * d + b // (d ** a1)) // a
    
    while c not in (d, e):
        c, d, e = d, e, (a1 * e + b // (e ** a1)) // a
    
    return min(d, e)

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

# RSA Broadcast Attack (Coppersmith's Attack)
def rsa_broadcast_attack(rsa_c: [bytes], rsa_n: [int], e: int) -> bytes:
    rsa_m = []
    for i, n in enumerate(rsa_n):
        rsa_m.append(reduce(lambda x, y: x * y, rsa_n[:i] + rsa_n[i + 1:]))
    
    t = [int.from_bytes(c, "big") * m * mod_inv(m, n) for (c, m, n) in zip (rsa_c, rsa_m, rsa_n)]
    
    c = sum(t) % reduce(lambda x, y: x * y, rsa_n)

    return int_to_bytes(root(e, c))

def c40(rsa_ciphertexts: [bytes], rsa_n: [int], e: int) -> bytes:
    return rsa_broadcast_attack(rsa_ciphertexts, rsa_n, e)
