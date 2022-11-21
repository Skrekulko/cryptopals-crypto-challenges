#
#   36 - Implement Secure Remote Password (SRP)
#

from requests import get
from cryptopals.s05.c36.client_c36 import client_c36


def test_c36() -> None:
    # Server's Session Key Address
    server_address = "http://127.0.0.1:8082/session_key"
    
    # Client's Session Key 'K'
    K_C = client_c36()
    
    # Server's Session Key 'K'
    K_S = get(server_address).json().get("K")
    
    assert K_C == K_S
