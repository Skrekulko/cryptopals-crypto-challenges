#
#   29 - Break a SHA-1 keyed MAC using length extension
#

from cryptopals.oracle import HashOracle
from cryptopals.utils import Generator
from cryptopals.hash import SHA1


class MyOracle(HashOracle):
    def __init__(self) -> None:
        self.key = Generator.random_bytes()
        
    def validate(self, plaintext: bytes, digest: bytes) -> bool:
        return SHA1.digest(self.key + plaintext) == digest
        
    def digest(self, plaintext: bytes) -> bytes:
        return SHA1.digest(self.key + plaintext)


class Decipher:
    @staticmethod
    def sha1_length_extension_attack(
            oracle: HashOracle,
            original_mac: bytes,
            original_plaintext: bytes,
            new_plaintext: bytes
    ) -> [bytes, bytes]:
        # Try Different Key Sizes
        for key_size in range(129):
            # Forged Message '(original-plaintext || glue-padding || new-plaintext)'
            forged_message = SHA1.padding(
                Generator.random_bytes(key_size, key_size) + original_plaintext
            )[key_size:] + new_plaintext

            # Split Digest Into Registers
            h_registers = [original_mac[i * 4:i * 4 + 4] for i in range(len(original_mac) // 4)]

            # Forged MAC Including The New Plaintext With Size Of '(key-size + forged-message-length)'
            forged_mac = SHA1.digest(new_plaintext, key_size + len(forged_message), h_registers)

            if oracle.validate(forged_message, forged_mac):
                return forged_message, forged_mac

        # Unable To Guess The Key Size
        raise Exception("Unable to forge the new plaintext!")
