#
#   25 - Break "random access read/write" AES CTR
#

from c25 import c25
from helper_c25 import Generator, AES128CTR
import codecs

def test_c25() -> None:
    # Load Strings From File
    file_name = "25.txt"
    with open(file_name) as file:
        data = codecs.decode(bytes(file.read().encode("ascii")), "base64")
        
    # Randomly Generated Key
    key = Generator.generate_key_128b()
    
    # Randomly Generated Nonce
    nonce = Generator.generate_random_int(1, (1 << 16) - 1)
    
    # Encrypt The Data
    ciphertext = AES128CTR.transform(data, key, nonce)

    assert c25(ciphertext, key, nonce) == data
