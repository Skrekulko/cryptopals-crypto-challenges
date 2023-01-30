#
#   42 - Bleichenbacher's e=3 RSA Attack
#

import re
from cryptopals.oracle import Oracle
from cryptopals.asymmetric import RSA
from cryptopals.hash import SHA1
from cryptopals.utils import Converter


class Math:
    @staticmethod
    def root_binary(x, n):
        # Initial Guess
        guess = 1

        # Counter For Steps
        step = 1

        while True:
            w = (guess + step) ** n
            if w == x:
                return (guess + step,) * 2
            elif w < x:
                step <<= 1
            elif step == 1:
                return guess, guess + 1
            else:
                guess += step >> 1
                step = 1


class MyOracle(Oracle):
    def __init__(self) -> None:
        # Key Size Bits
        self.key_length = 1024

        # RSA
        self.rsa = RSA(key_len=self.key_length)

        # Hashes Of Ciphertexts (Empty)
        self.hashes = []

        # Default Plaintext
        self.plaintext = b"armoring"

        # Default Ciphertext
        self.ciphertext = self.rsa.encrypt(plaintext=self.plaintext)

        # Default Hash Of The Ciphertext (For Testing Purposes)
        self.hashes.append(SHA1.digest(m=self.ciphertext))

    def encrypt(self, plaintext=b"") -> bytes:
        return self.rsa.encrypt(plaintext=plaintext)

    def decrypt(self, ciphertext=b"", key=b"", iv=b"") -> bytes:
        return self.rsa.decrypt(ciphertext=ciphertext)

    def verify(self, signature: bytes, data: bytes) -> bool:
        # Decrypt The Signature By Encrypting
        signature = b"\x00" + self.encrypt(signature)

        # Verify The Signature (Block In PKCS1.5 Standard Format)
        r = re.compile(b"\x00\x01\xff+?\x00.{15}(.{20})", re.DOTALL)
        m = r.match(signature)

        if not m:
            return False

        # Get The Hash
        data_hash = m.group(1)

        # Compare
        return data_hash == SHA1.digest(m=data)


def bleichenbacher_signature(key_size: int, data: bytes) -> bytes:
    # Craft A PKCS1.5 Standard Format Block
    crafted_block =\
        b"\x00\x01\xff\x00" +\
        b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"\
        + SHA1.digest(m=data)

    # Append Junk Bytes
    junk_bytes = (((key_size + 7) // 8) - len(crafted_block)) * b"\x00"
    crafted_block += junk_bytes

    # Forge A Signature By Finding Cube Root Of The Crafted Block
    forged_signature = Math.root_binary(int.from_bytes(crafted_block, "big"), 3)

    return Converter.int_to_hex(integer=forged_signature[1])
