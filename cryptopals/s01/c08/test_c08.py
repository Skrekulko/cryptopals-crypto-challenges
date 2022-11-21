#
#   08 - Detect AES in ECB mode
#

from cryptopals.utils import load_data
from cryptopals.s01.c08.solution_c08 import Detector


def test_c08() -> None:
    # Name Of The Data File
    file_name = "8.txt"
    
    # Valid Result
    result = True
    
    assert Detector.repeating_blocks(load_data(file_name)) == result
