#
#   39 - Implement RSA
#

from Crypto.Util.number import getPrime
from cryptopals.utils import Converter


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
    # Extended GCD
    def extended_gcd(aa: int, bb: int) -> [int]:
        lastremainder, remainder = abs(aa), abs(bb)

        x, lastx, y, lasty = 0, 1, 1, 0

        while remainder:
            lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
            x, lastx = lastx - quotient * x, x
            y, lasty = lasty - quotient * y, y

        return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

    @staticmethod
    # Modular Inverse
    def mod_inv(a: int, m: int) -> int:
        g, x, y = Math.extended_gcd(a, m)

        if g != 1:
            raise ValueError

        return x % m


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
