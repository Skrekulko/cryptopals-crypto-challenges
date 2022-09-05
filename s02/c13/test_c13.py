#
#   13 - ECB cut-and-paste
#

from c13 import c13

def test_c13() -> None:
    result = b"email=AAAAAAAAAAAAA&uid=10&role=admin"

    assert c13() == result
