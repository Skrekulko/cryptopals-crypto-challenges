#
#   29 - Break a SHA-1 keyed MAC using length extension
#

from cryptopals.s04.c29.solution_c29 import MyOracle, Decipher


def test_c29() -> None:
    # Original Plaintext
    original_plaintext = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    
    # New Plaintext (To Be Appended)
    new_plaintext = b";admin=true"
    
    # Oracle
    oracle = MyOracle()
    
    # Get The MAC '(key || original-message)'
    mac = oracle.digest(original_plaintext)
    
    # Forged Message And Corresponding MAC
    forged_message, forged_mac = Decipher.sha1_length_extension_attack(oracle, mac, original_plaintext, new_plaintext)
 
    assert new_plaintext in forged_message
