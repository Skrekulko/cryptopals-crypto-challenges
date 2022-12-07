#
#   41 - Implement unpadded message recovery oracle
#

from cryptopals.oracle import Oracle
from cryptopals.asymmetric import RSA
from cryptopals.hash import SHA1


class MyOracle(Oracle):
    def __init__(self) -> None:
        # Key Length In Bits
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
        ciphertext = self.rsa.encrypt(plaintext=plaintext)

        digest = SHA1.digest(ciphertext)

        if digest in self.hashes:
            raise Exception("Duplicate hash found!")

        self.hashes.append(digest)

        return ciphertext

    def decrypt(self, ciphertext=b"", key=b"", iv=b"") -> bytes:
        digest = SHA1.digest(m=ciphertext)

        if digest in self.hashes:
            raise Exception("Duplicate hash found!")

        return self.rsa.decrypt(ciphertext=ciphertext)
