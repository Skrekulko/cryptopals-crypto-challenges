#
#   46 - RSA parity oracle
#

from cryptopals.s06.c46.solution_c46 import Oracle
from cryptopals.utils import Converter
from math import ceil, log
from decimal import Decimal, getcontext


def rsa_parity_attack(oracle: Oracle, ciphertext: int) -> int:
    # Compute The Ciphertext Of 2, Which Is Used As The Ciphertext Multiplier
    multiplier = pow(2, oracle.parameters.e, oracle.parameters.n)

    # Initialize The Lower And The Upper Bound, And Use Decimal To Allow Better Precision
    lower_bound = Decimal(0)
    upper_bound = Decimal(oracle.parameters.n)

    # Number Of Iterations Needed
    k = int(ceil(log(oracle.parameters.n, 2)))

    # Precision Floating Point Number
    getcontext().prec = k

    # Binary Search
    for _ in range(k):
        ciphertext = (ciphertext * multiplier) % oracle.parameters.n

        if oracle.is_parity_odd(ciphertext):
            lower_bound = (lower_bound + upper_bound) / 2
        else:
            upper_bound = (lower_bound + upper_bound) / 2

    # Return The Binary Version Of The Upper bound
    return int(upper_bound)


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
