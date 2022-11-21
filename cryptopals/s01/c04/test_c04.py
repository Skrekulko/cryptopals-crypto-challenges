#
#   04 - Detect single-character XOR
#

from cryptopals.s01.c04.solution_c04 import load_lines, Detector


def test_c04() -> None:
    # Name Of The Data File
    file_name = "4.txt"
    
    # Valid Result
    result = b"Now that the party is jumping\n"
    
    assert Detector.single_character_xor(load_lines(file_name))[0] == result
