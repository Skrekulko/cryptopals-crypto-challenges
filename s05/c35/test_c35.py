#
#   35 - Implement DH with negotiated groups, and break with malicious "g" parameters
#

from c35 import c35, DiffieHellman

def test_c35() -> None:
    # Alice
    Alice = DiffieHellman()
    alice_message = b"Hello!"
    
    # Bob
    Bob = DiffieHellman()
    
    # g == 1
    g = 1
    assert c35(g, Alice, alice_message, Bob) == alice_message
    
    # g == p
    g = Alice.p
    assert c35(g, Alice, alice_message, Bob) == alice_message
    
    # g == (p - 1)
    g = (Alice.p - 1)
    assert alice_message in c35(g, Alice, alice_message, Bob)
    