#
#   35 - Implement DH with negotiated groups, and break with malicious "g" parameters
#

from random import randint
from helper_c35 import AES128CBC, Generator, PKCS7, SHA1, mod_pow

# Diffie-Hellman Implementation
class DiffieHellman():
    def __init__(
        self,
        g = 2,
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    ):
        # Generator
        self.g = g
        
        # Prime
        self.p = p
        
        # Secret Key
        self._secret_key = randint(0, p - 1)
        
        # Public Key
        self.public_key = mod_pow(self.g, self._secret_key, self.p)
        
        # Shared Secret Key
        self.shared_secret_key = None
        
    def recalculate_public_key(self) -> None:
        self.public_key = mod_pow(self.g, self._secret_key, self.p)
    
    def get_public_key(self) -> int:
        return self.public_key
        
    def set_shared_secret_key(self, other_party_public_key) -> None:
        self.shared_secret_key = mod_pow(other_party_public_key, self._secret_key, self.p)
        
    def get_shared_secret_key(self) -> int:
        return self.shared_secret_key

def malicious_g_attack(g: int, Alice: DiffieHellman, alice_message: bytes, Bob: DiffieHellman) -> [bytes]:
    # Step 1: Alice Sends 'p' And 'g' To Bob (Intercepted By Eva)
    p = Alice.p
    Bob.g = g
    Bob.recalculate_public_key()
    
    # Step 2: Bob Receives Forced 'g' And Sends ACK To Alice
    
    # Step 3: Alice Sends Her Public Key 'A' To Bob (Intercepted By Eva)
    A = Alice.get_public_key()
    Bob.set_shared_secret_key(A)
    
    # Step 4: Bob Sends His Public Key
    B = Bob.get_public_key()
    Alice.set_shared_secret_key(B)
    
    # Step 5: Alice Sends Her Encrypted Message To Bob (Intercepted And Relayed By Eva)
    _shared_secret_key = Alice.get_shared_secret_key()
    _shared_secret_key_len = (max(_shared_secret_key.bit_length(), 1) + 7) // 8
    _shared_secret_key_bytes = _shared_secret_key.to_bytes(_shared_secret_key_len, "big")
    _key = SHA1(_shared_secret_key_bytes)[:AES128CBC.block_size]
    _iv = Generator.generate_random_bytes(16, 16)
    _encrypted_message = AES128CBC.encrypt(alice_message, _key, _iv) + _iv
    
    # Step 6: Bob Receives The Encrypted Message From Alice
    
    # Get The IV For AES
    mitm_iv = _encrypted_message[-AES128CBC.block_size:]
    
    # Get The Secret Key For AES
    # g == 1
    if g == 1:
        mitm_key = SHA1(b"\x01")[:AES128CBC.block_size]
        mitm_message = AES128CBC.decrypt(_encrypted_message[:-AES128CBC.block_size], mitm_key, mitm_iv)
    # g == p
    elif g == Alice.p:
        mitm_key = SHA1(b"\x00")[:AES128CBC.block_size]
        mitm_message = AES128CBC.decrypt(_encrypted_message[:-AES128CBC.block_size], mitm_key, mitm_iv)
    # g == (p - 1): (-1)^(ab) => (+1 % p) || (-1 % p)
    else:
        # Both Possible Decrypted Messages
        mitm_message = []
        
        # Try For Each Secret Key
        for candidate in [1, p - 1]:
            mitm_key_len = (max(candidate.bit_length(), 1) + 7) // 8
            mitm_key_bytes = candidate.to_bytes(mitm_key_len, "big")
            mitm_key = SHA1(mitm_key_bytes)[:AES128CBC.block_size]
            
            # Decrypt
            try:
                mitm_message.append(AES128CBC.decrypt(_encrypted_message[:-AES128CBC.block_size], mitm_key, mitm_iv))
            except ValueError:
                continue
    
    return mitm_message

def c35(g: int, Alice: DiffieHellman, alice_message: bytes, Bob: DiffieHellman) -> [bytes]:
    return malicious_g_attack(g, Alice, alice_message, Bob)
