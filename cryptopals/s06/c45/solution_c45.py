#
#   43 - DSA key recovery from nonce
#

from Crypto.PublicKey import DSA as CryptoDSA
from Crypto.Random.random import randint
from cryptopals.utils import Math
from cryptopals.hash import SHA1

class DSA:
    def __init__(self, bits=2048, bypass=False):
        # Generate DSA Parameters
        self.parameters = CryptoDSA.generate(bits=bits)

        # Bypass Security Measures
        self.bypass = bypass

    def sign(self, message: bytes, x = None, k = None) -> [int, int]:
        # Private Key 'x'
        if x is not None:
            self.parameters.x = x

        # Pre-Message Secret Number 'k'
        if k is None:
            k = randint(1, self.parameters.q - 1)

        # First Component 'r'
        r = Math.mod_pow(
            b=self.parameters.g,
            e=k,
            m=self.parameters.p
        ) % self.parameters.q

        # The Leftmost min(N, outlen) Bits Of Hash(M)
        digest = int.from_bytes(SHA1.digest(m=message), "big")
        digest_len = digest.bit_length()
        z = digest >> (digest_len - Math.gcd(self.parameters.q.bit_length(), digest_len))

        # Second Component 's'
        s = Math.mod_inv(a=k, m=self.parameters.q) * (z + self.parameters.x * r) % self.parameters.q

        return r, s

    def verify(self, message: bytes, r: int, s: int) -> bool:
        # Check Boundaries
        if not self.bypass:
            if not (0 < r < self.parameters.q and 0 < s < self.parameters.q):
                return False

        ## Modular Inverse 's^-1' Of The Second Component 's'
        w = Math.mod_inv(s, self.parameters.q) % self.parameters.q

        # The Leftmost min(N, outlen) Bits Of Hash(M')
        digest = int.from_bytes(SHA1.digest(m=message), "big")
        digest_len = digest.bit_length()
        z = digest >> (digest_len - Math.gcd(self.parameters.q.bit_length(), digest_len))

        u1 = z * w % self.parameters.q

        u2 = r * w % self.parameters.q

        v = (
            Math.mod_pow(self.parameters.g, u1, self.parameters.p) *
            Math.mod_pow(self.parameters.y, u2, self.parameters.p)
        ) % self.parameters.p % self.parameters.q

        if v == r:
            return True

        return False
