#
#   28 - Implement a SHA-1 keyed MAC
#

from cryptopals.s04.c28.solution_c28 import SHA1
from Crypto.Hash import SHA1 as CRYPTOSHA1


def test_c28() -> None:
    # Message
    message = b"abc" * 64
    
    # Test Out Implementation
    assert SHA1.digest(message) == bytes.fromhex(CRYPTOSHA1.new(message).hexdigest())
    
    # Key
    key = b"0123456789"
    
    # Get MAC Hash
    mac = SHA1.digest(key + message)
    
    # Modify First Byte
    modified_mac = SHA1.digest(key + (b"d" + message[1:]))
    
    # Verify Both Hashes
    assert mac != modified_mac
