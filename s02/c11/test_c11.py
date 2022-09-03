#
#   11 - An ECB/CBC detection oracle
#

from c11 import c11

def test_c11() -> None:
    input = b"A" * 50
    result = c11(input)

    assert result[0] == result[1]