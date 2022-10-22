#
#   26 - CTR bitflipping
#

from helper_c26 import fixed_xor, Generator, AES128CTR

class OracleCTR:
    def __init__(self):
        self.key = Generator.generate_key_128b()
        self.nonce = Generator.generate_random_int(1, (1 << 16) - 1)
    
    @staticmethod
    def parse_input(input: bytes) -> bytes:
        # Remove Unwated Characters ';' And '='
        filtered_input = bytes(byte for byte in input if byte != int.from_bytes(b";", "big") and byte != int.from_bytes(b"=", "big"))
        
        to_prepend = b"comment1=cooking%20MCs;userdata="
        print(f"to_prepend len = {len(to_prepend)}")
        to_append = b";comment2=%20like%20a%20pound%20of%20bacon"
        return (to_prepend + filtered_input + to_append)
    
    @staticmethod
    def is_admin(input: bytes) -> bool:
        return b";admin=true;" in input
    
    def encrypt(self, input: bytes) -> bytes:
        return AES128CTR.transform(OracleCTR.parse_input(input), self.key, self.nonce)
        
    def decrypt_and_check_admin(self, encrypted_input: bytes) -> {bool, bytes}:
        decrypted = AES128CTR.transform(encrypted_input, self.key, self.nonce)
        is_admin = OracleCTR.is_admin(decrypted)
        
        return {"admin": is_admin, "decrypted": decrypted}

def oracle_ctr_bit_flipping() -> bool:
    oracle = OracleCTR()
    
    # No Input Length
    no_input = oracle.encrypt(b"")
    no_input_len = len(no_input)
    print(no_input)
    print(no_input[:32])
    print(len(no_input[:32]))
    print(no_input[32:])
    print(len(no_input[32:]))
    print(f"no_input_len = {no_input_len}")
    
    # Crafted Admin
    admin = b";admin=true"
    admin_len = len(admin)
    
    # Crafted Input
    crafted_input = b"A" * admin_len
    
    # Encrypt Crafted Input And Find Offset
    encrypted = oracle.encrypt(crafted_input)
    for index, (b1, b2) in enumerate(zip(no_input, encrypted)):
        if b1 == b2:
            offset = index + 1
        else:
            break
    
    encrypted_input = encrypted[offset : offset + admin_len]
    
    # Calculate Keystream Bytes
    keystream = fixed_xor(encrypted_input, crafted_input)
    
    # Calculate XORed Admin Bytes
    xored_admin = fixed_xor(keystream, admin)
    
    # Modify Encrypted Data
    modified = encrypted[:offset] + xored_admin + encrypted[offset + admin_len:]
    
    # Decrypt
    decrypted = oracle.decrypt_and_check_admin(modified)
    
    return decrypted["admin"]
    
def c26():
    return oracle_ctr_bit_flipping()