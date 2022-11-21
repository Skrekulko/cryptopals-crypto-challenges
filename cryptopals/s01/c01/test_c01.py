#
#   01 - Convert hex to base64
#

from cryptopals.s01.c01.solution_c01 import Converter


def test_c01() -> None:
    # Input String
    string = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    
    # Valid Result
    result = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    
    assert Converter.hex_to_base64(string) == result
