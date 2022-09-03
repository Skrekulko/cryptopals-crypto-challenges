#
#   09 - Implement PKCS#7 padding
#

from c09 import c09

def test_c09() -> None:
    input = b"YELLOW SUBMARINE"
    block_size = 20
    result = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    
    assert c09(input, block_size) == result