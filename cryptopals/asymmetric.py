from Crypto.PublicKey import RSA as CryptoRSA
from cryptopals.utils import Math, Generator
from cryptopals.utils import Converter


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

        # # Public Exponent 'e'
        # self.e = e
        #
        # phi = 0
        # while Math.gcd(self.e, phi) != 1:
        #     # Secret Primes 'p' And 'q' (q < p)
        #     p, q = getPrime(key_len // 2), getPrime(key_len // 2)
        #
        #     phi = Math.lcm(p - 1, q - 1)
        #
        #     # Public Modulus 'n'
        #     self.n = p * q
        #
        # # Secret Exponent 'd'
        # self._d = Math.mod_inv(self.e, phi)

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
