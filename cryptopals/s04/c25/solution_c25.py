#
#   25 - Break "random access read/write" AES CTR
#

from cryptopals.symmetric import AES128CTR
from cryptopals.xor import XOR


def edit(ciphertext: bytes, key: bytes, nonce: int, offset: int, my_plaintext: bytes) -> bytes:
    # Decrypt The Ciphertext
    plaintext = AES128CTR.transform(ciphertext, key, nonce)

    # Encrypt The New Plaintext
    return AES128CTR.transform(
        # Replace The Original Plaintext With A New Plaintext
        plaintext[:offset] + my_plaintext + plaintext[offset + len(my_plaintext):],
        key,
        nonce
    )


class Decipher:
    @staticmethod
    def aes_ctr_recover(ciphertext: bytes, key: bytes, nonce: int):
        # Craft A New Plaintext
        crafted_plaintext = b"A" * len(ciphertext)

        # Edit The Ciphertext
        new_ciphertext = edit(ciphertext, key, nonce, 0, crafted_plaintext)

        # XOR Known Plaintext With New Ciphertext
        xored = XOR.fixed(new_ciphertext, crafted_plaintext)

        # Recover Original Plaintext
        recovered_plaintext = XOR.fixed(ciphertext, xored)

        return recovered_plaintext
