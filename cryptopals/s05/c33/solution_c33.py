#
#   33 - Implement Diffie-Hellman
#

from cryptopals.generator import Generator


class Math:
    @staticmethod
    # Modular Exponentiation 'a^b mod m'
    def mod_pow(b: int, e: int, m: int) -> int:
        x = 1

        while e > 0:
            b, e, x = (
                b * b % m,
                e // 2,
                b * x % m if e % 2 else x
            )

        return x


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
