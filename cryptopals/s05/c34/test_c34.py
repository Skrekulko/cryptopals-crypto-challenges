#
#   34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
#

from cryptopals.s05.c34.solution_c34 import Decipher
from cryptopals.asymmetric import DiffieHellman


def test_c34() -> None:
    # Alice
    alice = DiffieHellman()
    alice_plaintext = b"Hello!"
    
    # Bob
    bob = DiffieHellman()
    bob_plaintext = b"Hello!"

    assert Decipher.dh_parameter_injection(
        alice, alice_plaintext,
        bob, bob_plaintext
    ) == (alice_plaintext, bob_plaintext)
