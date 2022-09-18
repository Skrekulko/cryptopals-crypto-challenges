#
#   17 - The CBC padding oracle
#

from c17 import c17

def test_c17() -> None:
    assert c17() == True
