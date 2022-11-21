#
#   39 - Implement RSA
#

from Crypto.Util.number import getPrime
from cryptopals.converter import Converter


class Math:
    @staticmethod
    # Greatest Common Divider
    def gcd(a: int, b: int) -> int:
        return Math.gcd(b, a % b) if b else abs(a)

    @staticmethod
    # Least Common Multiple
    def lcm(a: int, b: int) -> int:
        return abs(a * b) // Math.gcd(a, b) if a and b else 0

    @staticmethod
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


class RSA:
    def __init__(self, key_len: int, e=3):
        # Public Exponent 'e'
        self.e = e
        
        phi = 0
        while Math.gcd(self.e, phi) != 1:
            # Secret Primes 'p' And 'q' (q < p)
            p, q = getPrime(key_len // 2), getPrime(key_len // 2)
            
            phi = Math.lcm(p - 1, q - 1)
            
            # Public Modulus 'n'
            self.n = p * q
        
        # Secret Exponent 'd'
        self._d = Math.mod_inv(self.e, phi)
        
    def encrypt(self, plaintext: bytes) -> bytes:
        return Converter.int_to_hex(
            pow(
                int.from_bytes(plaintext, "big"),
                self.e,
                self.n
            )
        )
        
    def decrypt(self, ciphertext: bytes) -> bytes:
        return Converter.int_to_hex(
            pow(
                int.from_bytes(ciphertext, "big"),
                self._d,
                self.n
            )
        )
