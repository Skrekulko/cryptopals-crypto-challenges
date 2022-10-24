#
#   33 - Implement Diffie-Hellman
#

from c33 import c33, DiffieHellman

def test_c33() -> None:
    # Party A
    DH_A = DiffieHellman()
    
    # Party B
    DH_B = DiffieHellman()

    assert c33(DH_A, DH_B) == True