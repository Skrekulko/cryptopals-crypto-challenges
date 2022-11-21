#
#   27 - Recover the key from CBC with IV=Key
#

from cryptopals.s04.c27.solution_c27 import MyOracle, Decipher


def test_c27() -> None:
    # Oracle
    oracle = MyOracle()
    
    assert Decipher.aes_cbc_iv_key(oracle) == oracle.key
