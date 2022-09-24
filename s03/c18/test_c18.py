#
#   18 - Implement CTR, the stream cipher mode
#

from c18 import c18

def test_c18() -> None:
    input_plaintext = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    input_encrypted = b""
    
    assert c18()["encrypted"] == input_encrypted
    
    assert c18()["decrypted"] == input_plaintext
