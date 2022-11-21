#
#   11 - An ECB/CBC detection oracle
#

from os import urandom
from random import randint, getrandbits
from cryptopals.symmetric import AES128ECB, AES128CBC
from cryptopals.oracle import Oracle


class Generator:
    @staticmethod
    def random_bytes(min_value=1, max_value=16) -> bytes:
        return urandom(randint(min_value, max_value))

    @staticmethod
    def key_128b() -> bytes:
        return urandom(16)

    @staticmethod
    def true_or_false() -> bool:
        return bool(getrandbits(1))


class MyOracle(Oracle):
    def encrypt(self, plaintext=b"") -> [str, bytes]:
        key = Generator.key_128b()
        iv = Generator.key_128b()
        header_bytes = Generator.random_bytes(5, 10)
        footer_bytes = Generator.random_bytes(5, 10)
        padded_plaintext = header_bytes + plaintext + footer_bytes

        if Generator.true_or_false():
            return "ecb", AES128ECB.encrypt(padded_plaintext, key)
        else:
            return "cbc", AES128CBC.encrypt(padded_plaintext, key, iv)
