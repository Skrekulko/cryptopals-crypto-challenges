#
#   32 - Break HMAC-SHA1 with a slightly less artificial timing leak
#

import requests
from cryptopals.s04.c32.server_c32 import MySHA1
from cryptopals.s04.c31.solution_c31 import Decipher


def test_c32() -> None:
    # Get Server Key
    response = requests.get(f"http://127.0.0.1:8082/key")
    server_key = bytes.fromhex(response.text)

    # Filename
    filename = b"foo"

    # Known HMAC Length
    HMAC_LEN = 20

    # Number Of Rounds (Increases The Statistical Probability Of Guessing The Correct HMAC Bytes)
    rounds = 5

    # Maximum HMAC Bytes To Get (Testing Purposes)
    max_hmac_bytes = 4

    assert \
        Decipher.hmac_timing_attack(filename, HMAC_LEN, rounds, max_hmac_bytes) \
        == MySHA1.hmac(server_key, filename)[:max_hmac_bytes]
