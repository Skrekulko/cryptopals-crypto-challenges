#
#   15 - PKCS#7 padding validation
#

import pytest
from c15 import c15

def test_c15() -> None:
    input = b"ICE ICE BABY\x04\x04\x04\x04"
    input_incorrect_1 = b"ICE ICE BABY\x05\x05\x05\x05"
    input_incorrect_2 = b"ICE ICE BABY\x01\x02\x03\x04"
    result = b"ICE ICE BABY"
    
    with pytest.raises(ValueError):
        c15(input_incorrect_1)
        
    with pytest.raises(ValueError):
        c15(input_incorrect_2)
    
    assert c15(input) == result
