#
#   13 - ECB cut-and-paste
#

from itertools import count
from helper_c13 import decrypt_aes_ecb, pkcs7_padding, Generator, encrypt_aes_ecb

class Profile:
    def __init__(self):
        self.key = Generator.generate_key_128b()
        
    @staticmethod
    def profile_for(email: bytes) -> bytes:
        # Remove Unwated Characters '&' And '='
        filtered_email = bytes(byte for byte in email if byte != int.from_bytes(b"&", "big") and byte != int.from_bytes(b"=", "big"))
        return b"email=" + filtered_email + b"&uid=10&role=user"
        
    def encrypt_profile(self, email):
        return encrypt_aes_ecb(self.profile_for(email), self.key)
        
    def decrypt_profile(self, encrypted_profile):
        return decrypt_aes_ecb(encrypted_profile, self.key)
    
def hijack_user_role() -> bytes:
    # Create Profile Manager
    manager = Profile()
    
    # Detect Block Size
    block_size = 0
    for i in count(start = 0):
        encrypted1 = manager.encrypt_profile(b"A" * i)
        encrypted2 = manager.encrypt_profile(b"A" * (i + 1))
        encrypted1_len = len(encrypted1)
        encrypted2_len = len(encrypted2)
        
        if encrypted2_len > encrypted1_len:
            block_size = encrypted2_len - encrypted1_len
            break
    
    # Automated Attack
    target_block = b""
    for i in count(start = 0):
        crafted_role = pkcs7_padding(b"admin", block_size)
        crafted_email = i * b"A" + crafted_role
        profile = manager.profile_for(crafted_email)
        padded_profile = pkcs7_padding(profile, block_size)
        padded_profile_blocks = list(profile[i * block_size : i * block_size + block_size] for i in range(len(padded_profile) // block_size))

        try:
            index = padded_profile_blocks.index(crafted_role)
            encrypted = manager.encrypt_profile(crafted_email)
            target_block = encrypted[index * block_size : (index + 1) * block_size]
            break
        except ValueError:
            continue
        
    for i in count(start = 0):
        crafted_email = i * b"A"
        profile = manager.profile_for(crafted_email)
        padded_profile = pkcs7_padding(profile, block_size)
        padded_profile_blocks = list(profile[i * block_size : i * block_size + block_size] for i in range(len(padded_profile) // block_size))

        if b"user" in padded_profile_blocks:
            encrypted = manager.encrypt_profile(crafted_email)
            hijacked_encrypted = encrypted[:-block_size] + target_block
            decrypted = manager.decrypt_profile(hijacked_encrypted)
            break

    return decrypted

def c13():
    return hijack_user_role()