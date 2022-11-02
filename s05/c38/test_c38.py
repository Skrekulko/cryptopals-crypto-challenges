#
#   38 - Offline dictionary attack on simplified SRP
#

import json
from requests import get
from server_c38 import app
from client_c38 import client_c38

# Load Agreed Value 'N'
def load_agreed_value() -> None:
    # JSON File Containing Agreed Values
    file_name = "agreed_values.json"
    
    try:
        with open(file_name, "r") as file:
            agreed_values = json.load(file)
            N = agreed_values["N"]  # Large Safe Prime
            return N
    except FileNotFoundError:
        return None

def test_c38() -> None:
    # Server's Session Key Address
    server_address = "http://127.0.0.1:8082/session_key"
    
    # Large Safe Prime
    N = load_agreed_value()
    
    # Client's Session Key 'K'
    K_C = client_c38()
    
    # Server's Session Key 'K'
    K_S = get(server_address).json().get("K")

    assert K_C == K_S
