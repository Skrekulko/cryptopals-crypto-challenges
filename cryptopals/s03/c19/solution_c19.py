#
#   19 - Break fixed-nonce CTR mode using substitutions
#

from cryptopals.solver import Decipher
from cryptopals.xor import XOR


class MyDecipher(Decipher):
    @staticmethod
    def aes_ctr_fixed_nonce(ciphertexts: list) -> list[bytes]:
        # Construct The Keystream
        keystream = b""
        for i in range(max(map(len, ciphertexts))):
            # Construct A Column Of nth Ciphertext Characters
            column = b""
            for ciphertext in ciphertexts:
                column += ciphertext[i].to_bytes(1, "little") if i < len(ciphertext) else b""

            # Break The Single Byte Using Frequency Analysis
            keystream += Decipher.single_byte_xor(column)[1].to_bytes(1, "little")

        # Decrypt The Ciphertexts
        plaintexts = []
        for ciphertext in ciphertexts:
            plaintexts.append(XOR.repeating(ciphertext, keystream))

        return plaintexts
