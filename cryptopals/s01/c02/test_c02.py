#
#   02 - Fixed XOR
#

from cryptopals.s01.c02.solution_c02 import fixed_xor


def test_c02() -> None:
    # Input Byte Strings
    byte_string1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    byte_string2 = bytes.fromhex("686974207468652062756c6c277320657965")

    # Valid Result
    result = bytes.fromhex("746865206b696420646f6e277420706c6179")
    
    assert fixed_xor(byte_string1, byte_string2) == result
