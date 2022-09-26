#
#   18 - Implement CTR, the stream cipher mode
#

from c18 import c18

def test_c18() -> None:
    input = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    key = b"YELLOW SUBMARINE"
    nonce = 0
    
    encrypted = c18(input, key, nonce)
    
    assert c18(encrypted, key, nonce) == input
