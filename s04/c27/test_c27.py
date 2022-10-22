#
#   27 - Recover the key from CBC with IV=Key
#

from c27 import Oracle, c27

def test_c27() -> None:
    oracle = Oracle()
    
    assert c27(oracle) == oracle.key