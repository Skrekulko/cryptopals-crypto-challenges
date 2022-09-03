#
#   08 - Detect AES in ECB mode
#

from c08 import c08

def test_c08() -> None:
    file_name = "8.txt"
    result = True
    
    assert c08(file_name) == result