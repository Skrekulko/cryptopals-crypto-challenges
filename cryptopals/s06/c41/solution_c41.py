#
#   41 - Implement unpadded message recovery oracle
#

from cryptopals.asymmetric import RSA
from cryptopals.hash import SHA1
from cryptopals.utils import Converter


class Oracle(RSA):
    def __init__(self, bits=2048, e=65537) -> None:
        # Initialize RSA
        super().__init__(bits=bits, e=e)

        # Hashes Of Ciphertexts (Empty)
        self.hashes = []

        # Default Plaintext
        self.plaintext = int.from_bytes(b"armoring", "big")

        # Default Ciphertext
        self.ciphertext = self.encrypt(message=self.plaintext)

        # Default Hash Of The Ciphertext (For Testing Purposes)
        self.hashes.append(SHA1.digest(m=Converter.int_to_hex(self.ciphertext)))

    def encrypt(self, message: int) -> int:
        ciphertext = super().encrypt(message=message)

        digest = SHA1.digest(m=Converter.int_to_hex(ciphertext))

        if digest in self.hashes:
            raise Exception("Duplicate hash found!")

        self.hashes.append(digest)

        return ciphertext

    def decrypt(self, message: int) -> int:
        digest = SHA1.digest(m=Converter.int_to_hex(message))

        if digest in self.hashes:
            raise Exception("Duplicate hash found!")

        return super().decrypt(message=message)
