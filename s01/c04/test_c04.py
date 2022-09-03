#
#   04 - Detect single-character XOR
#

from c04 import c04

def test_c04() -> None:
    file_name = "4.txt"
    result = b"Now that the party is jumping\n"
    
    assert c04(file_name)[0] == result