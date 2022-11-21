#
#   33 - Implement Diffie-Hellman
#

from cryptopals.s05.c33.solution_c33 import DiffieHellman


def test_c33() -> None:
    # Alice
    Alice = DiffieHellman()
    
    # Bob
    Bob = DiffieHellman()

    # Shared Secret Key
    Alice.set_ssk(Bob.pk)
    Bob.set_ssk(Alice.pk)

    assert Alice.ssk == Bob.ssk
