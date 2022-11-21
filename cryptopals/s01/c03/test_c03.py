#
#   03 - Single-byte XOR cipher
#

from cryptopals.s01.c03.solution_c03 import Decipher


def test_c03() -> None:
    # Hex Encoded String
    byte_string = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    
    # Valid Result
    result = b"Cooking MC's like a pound of bacon"
    
    assert Decipher.single_byte_xor_cipher(byte_string)[0] == result
