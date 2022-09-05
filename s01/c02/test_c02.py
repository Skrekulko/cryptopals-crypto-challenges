#
#   02 - Fixed XOR
#

from c02 import c02

def test_c02() -> None:
    input1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    input2 = bytes.fromhex("686974207468652062756c6c277320657965")
    result = bytes.fromhex("746865206b696420646f6e277420706c6179")
    
    assert c02(input1, input2) == result