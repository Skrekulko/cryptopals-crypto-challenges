#
#   37 - Break SRP with a zero key
#

import json
from requests import get
from cryptopals.s05.c37.client_c37 import client_c37


# Load Agreed Value 'N'
def load_agreed_value() -> int:
    # JSON File Containing Agreed Values
    file_name = "agreed_values.json"
    
    try:
        with open(file_name, "r") as file:
            agreed_values = json.load(file)
            N = agreed_values["N"]  # Large Safe Prime
            return N
    except FileNotFoundError:
        raise FileNotFoundError


def test_c37() -> None:
    # Server's Session Key Address
    server_address = "http://127.0.0.1:8082/session_key"
    
    # Large Safe Prime
    N = load_agreed_value()
    
    # Public Ephemera Key's 'A'
    public_keys = [None, 0, N, N * 2]
    
    # Try Different Public Keys
    for _ in public_keys:
        # Client's Session Key 'K'
        K_C = client_c37()
        
        # Server's Session Key 'K'
        K_S = get(server_address).json().get("K")
    
        assert K_C == K_S
