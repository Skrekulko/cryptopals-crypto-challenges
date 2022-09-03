#
#   03 - Single-byte XOR cipher
#

from c03 import c03

def test_c03() -> None:
    input = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    result = b"Cooking MC's like a pound of bacon"
    
    assert c03(input)[0] == result