#
#   29 - Break a SHA-1 keyed MAC using length extension
#

from c29 import c29, Oracle, SHA1

def test_c29() -> None:
    # Original Message
    original_message = (b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
    
    # New Message (To Be Appended)
    new_message = b";admin=true"
    
    # Oracle
    oracle = Oracle()
    
    # Get The MAC '(key || original-message)'
    mac = oracle.get_digest(original_message)
    
    # Forged Message And Corresponding MAC
    forged_message, forged_mac = c29(oracle, mac, original_message, new_message)
 
    assert new_message in forged_message