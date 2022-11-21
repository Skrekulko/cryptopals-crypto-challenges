#
#   11 - An ECB/CBC detection oracle
#

from cryptopals.Solver import Detector
from cryptopals.s02.c11.solution_c11 import MyOracle


def test_c11() -> None:
    # Plaintext
    plaintext = b"A" * 50

    # Oracle Result
    oracle_result = MyOracle().encrypt(plaintext)

    # Detector Result
    detector_result = Detector.repeating_blocks(oracle_result[1])

    assert detector_result == (True if (oracle_result[0] == "ecb") else False)
