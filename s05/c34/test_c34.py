#
#   34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
#

from c34 import DiffieHellman, c34

def test_c34() -> None:
    # Alice
    Alice = DiffieHellman()
    alice_message = b"Hello!"
    
    # Bob
    Bob = DiffieHellman()
    bob_message = b"Hello there!"

    assert c34(Alice, alice_message, Bob, bob_message) == (alice_message, bob_message)