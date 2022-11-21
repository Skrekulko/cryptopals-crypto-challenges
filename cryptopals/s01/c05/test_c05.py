#
#   05 - Implement repeating-key XOR
#

from cryptopals.s01.c05.solution_c05 import XOR


def test_c05() -> None:
    # Plaintext
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    
    # Secret Key
    key = b"ICE"
    
    # Valid Result
    result = bytes.fromhex(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527"
        +
        "2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )
    
    assert XOR.repeating_key_xor(plaintext, key) == result
