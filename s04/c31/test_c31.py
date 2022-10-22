#
#   31 - Implement and break HMAC-SHA1 with an artificial timing leak
#

import requests
from c31 import c31
from server_c31 import HMAC_SHA1

def test_c31() -> None:
    response = requests.get(f"http://127.0.0.1:8082/key")
    server_key = bytes.fromhex(response.text)
    filename = b"foo"
    assert c31() == HMAC_SHA1(server_key, filename)