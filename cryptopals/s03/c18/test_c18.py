#
#   18 - Implement CTR, the stream cipher mode
#

from cryptopals.s03.c18.solution_c18 import AES128CTR
from cryptopals.converter import Converter


def test_c18() -> None:
    # Ciphertext
    ciphertext = Converter.base64_to_hex(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    # Secret Key
    key = b"YELLOW SUBMARINE"

    # Secret Nonce
    nonce = 0

    # Valid Result
    result = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    
    assert AES128CTR.transform(ciphertext, key, nonce) == result
