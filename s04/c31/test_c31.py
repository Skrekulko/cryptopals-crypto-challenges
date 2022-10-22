#
#   31 - Implement and break HMAC-SHA1 with an artificial timing leak
#

import requests
from c31 import c31
from server_c31 import HMAC_SHA1

def test_c31() -> None:
    # Get Server Key
    response = requests.get(f"http://127.0.0.1:8082/key")
    server_key = bytes.fromhex(response.text)
    
    # Filename
    filename = b"foo"
    
    # Number Of Rounds (Incrases The Statistical Probability Of Guessing The Correct HMAC Bytes)
    rounds = 2
    
    assert c31(filename, rounds) == HMAC_SHA1(server_key, filename)