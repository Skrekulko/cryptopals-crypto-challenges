from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.PublicKey import DSA as CryptoDSA
from Crypto.Random.random import randint
from cryptopals.utils import Math, Generator
from cryptopals.utils import Converter
from cryptopals.hash import SHA1


class DiffieHellman:
    def __init__(
        self,
        g=2,
        p=int(
            "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF"
            "9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386B"
            "FB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DC"
            "A3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16
        )
    ):
        # Generator
        self.g = g

        # Safe Prime
        self.p = p

        # Secret Key
        self.sk = Generator.random_int(0, self.p - 1)

        # Public Key
        self.pk = Math.mod_pow(self.g, self.sk, self.p)

        # Shared Secret Key
        self.ssk = None

    def set_ssk(self, pk: int, sk=None, p=None) -> None:
        if sk is None:
            sk = self.sk

        if p is None:
            p = self.p

        self.ssk = Math.mod_pow(pk, sk, p)

    @staticmethod
    def calculate_sk(p: int) -> int:
        return Generator.random_int(0, p - 1)

    @staticmethod
    def calculate_pk(sk: int, g: int, p: int) -> int:
        return Math.mod_pow(g, sk, p)

    @staticmethod
    def calculate_ssk(pk: int, sk: int, p: int) -> int:
        return Math.mod_pow(pk, sk, p)


class RSA:
    def __init__(self, bits: int, e=65537):
        # Generate RSA Parameters
        self.parameters = CryptoRSA.generate(bits=bits, e=e)

    def encrypt(self, plaintext: bytes) -> bytes:
        return Converter.int_to_hex(
            pow(
                int.from_bytes(plaintext, "big"),
                self.parameters.e,
                self.parameters.n
            )
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        return Converter.int_to_hex(
            pow(
                int.from_bytes(ciphertext, "big"),
                self.parameters.d,
                self.parameters.n
            )
        )

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
