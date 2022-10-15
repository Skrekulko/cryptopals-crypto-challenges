#
#   28 - Implement a SHA-1 keyed MAC
#

from c28 import c28
from Crypto.Hash import SHA1 as CryptoSHA1

def test_c28() -> None:
    # Message
    message = b"abc"
    
    # Test Out Implementation
    assert c28(message) == bytes.fromhex(CryptoSHA1.new(message).hexdigest())
    
    # Key
    key = b"0123456789"
    
    # Get MAC Hash
    mac = c28(key + message)
    
    # Modify First Byte
    modified_mac = c28(key + (b"d" + message[1:]))
    
    # Verify Both Hashes
    assert mac != modified_mac