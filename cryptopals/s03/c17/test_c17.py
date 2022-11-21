#
#   17 - The CBC padding oracle
#

from cryptopals.s03.c17.solution_c17 import MyOracle, Decipher


def test_c17() -> None:
    # Oracle
    oracle = MyOracle()

    # Get The Plaintext String
    plaintext_string = Decipher.cbc_padding_oracle(oracle)

    assert oracle.check_string(plaintext_string)
