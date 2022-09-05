#
#   07 - AES in ECB mode
#

from c07 import c07

def test_c07() -> None:
    file_name = "7.txt"
    key = b"YELLOW SUBMARINE"
    result = b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin'"
    
    assert c07(file_name, key) == result