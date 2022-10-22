#
#   32 - Break HMAC-SHA1 with a slightly less artificial timing leak
#

import requests
from c32 import c32
from server_c32 import HMAC_SHA1

def test_c32() -> None:
    # Get Server Key
    response = requests.get(f"http://127.0.0.1:8082/key")
    server_key = bytes.fromhex(response.text)
    
    # Filename
    filename = b"foo"
    
    # Number Of Rounds (Incrases The Statistical Probability Of Guessing The Correct HMAC Bytes)
    rounds = 2
    
    assert c32(filename, rounds) == HMAC_SHA1(server_key, filename)