#
#   39 - Implement RSA
#

from Crypto.PublicKey import RSA as CryptoRSA
from cryptopals.utils import Math


class MyMath(Math):
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
    def __init__(self, bits=2048, e=65537) -> None:
        # Generate RSA Parameters
        self.parameters = CryptoRSA.generate(bits=bits, e=e)
        
    def encrypt(self, message: int) -> int:
        return Math.mod_pow(
            message,
            self.parameters.e,
            self.parameters.n
        )
        
    def decrypt(self, message: int) -> int:
        return Math.mod_pow(
            message,
            self.parameters.d,
            self.parameters.n
        )

    def sign(self, message: int) -> int:
        return self.decrypt(message=message)

    def verify(self, message: int, signature: int) -> bool:
        return self.encrypt(message=signature) == message
