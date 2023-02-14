#
#   46 - RSA parity oracle
#

from cryptopals.s06.c46.solution_c46 import Oracle, rsa_parity_attack
from cryptopals.utils import Converter


def test_c46() -> None:
    # RSA Oracle
    oracle = Oracle(e=3)

    # Message To Recover
    message = Converter.hex_to_int(
        hexadecimal=Converter.base64_to_hex(
            base64_bytes=b"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
        ), byteorder="big"
    )

    # Encrypted Message
    ciphertext = oracle.encrypt(message=message)

    # Recover The Message From Ciphertext And Compare
    assert rsa_parity_attack(oracle=oracle, ciphertext=ciphertext) == message
