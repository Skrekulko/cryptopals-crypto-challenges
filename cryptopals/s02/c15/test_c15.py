#
#   15 - PKCS#7 padding validation
#

import pytest
from cryptopals.pkcs import PKCS7


def test_c15() -> None:
    # Block Size
    block_size = 16

    # Padded Data
    padded_data = b"ICE ICE BABY\x04\x04\x04\x04"

    # Invalid Input 1
    invalid_input_1 = b"ICE ICE BABY\x05\x05\x05\x05"

    # Invalid Input 2
    invalid_input_2 = b"ICE ICE BABY\x01\x02\x03\x04"

    # Valid Result
    result = b"ICE ICE BABY"

    assert PKCS7.strip(padded_data, block_size) == result

    with pytest.raises(ValueError):
        PKCS7.strip(invalid_input_1, block_size)
        
    with pytest.raises(ValueError):
        PKCS7.strip(invalid_input_2, block_size)
