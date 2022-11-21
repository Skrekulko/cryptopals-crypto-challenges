#
#   35 - Implement DH with negotiated groups, and break with malicious "g" parameters
#

from cryptopals.s05.c35.solution_c35 import Decipher
from cryptopals.asymmetric import DiffieHellman


def test_c35() -> None:
    # Alice
    alice = DiffieHellman()
    alice_plaintext = b"Hello!"
    
    # Bob
    bob = DiffieHellman()
    
    # g == 1
    g = 1
    assert Decipher.dh_malicious_g(g, alice, alice_plaintext, bob) == alice_plaintext
    
    # g == p
    g = alice.p
    assert Decipher.dh_malicious_g(g, alice, alice_plaintext, bob) == alice_plaintext
    
    # g == (p - 1)
    g = (alice.p - 1)
    assert alice_plaintext in Decipher.dh_malicious_g(g, alice, alice_plaintext, bob)
    