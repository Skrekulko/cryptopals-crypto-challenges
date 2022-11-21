#
#   25 - Break "random access read/write" AES CTR
#

from cryptopals.s04.c25.solution_c25 import Decipher
from cryptopals.converter import Converter
from cryptopals.Generator import Generator
from cryptopals.symmetric import AES128CTR


def test_c25() -> None:
    # File Name
    file_name = "25.txt"

    # Decode The Base64 Encoded Strings Into Byte String
    with open(file_name) as file:
        plaintext = Converter.base64_to_hex(file.read().encode())

    # Randomly Generated Secret Key
    key = Generator.key_128b()
    
    # Randomly Generated Secret Nonce
    nonce = Generator.random_int(1, (1 << 16) - 1)
    
    # Encrypt The Data
    ciphertext = AES128CTR.transform(plaintext, key, nonce)

    assert Decipher.aes_ctr_recover(ciphertext, key, nonce) == plaintext
