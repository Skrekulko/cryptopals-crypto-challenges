#
#   36 - Implement DH with negotiated groups, and break with malicious "g" parameters
#

from requests import get
from server_c36 import app
from client_c36 import client_c36

def test_c36() -> None:
    # Server's Session Key Address
    server_address = "http://127.0.0.1:8082/session_key"
    
    # Client's Session Key 'K'
    K_C = client_c36()
    print(K_C)
    
    # Server's Session Key 'K'
    K_S = get(server_address).json().get("K")
    
    assert K_C == K_S