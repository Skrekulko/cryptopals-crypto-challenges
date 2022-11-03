#
#   34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
#

from random import randint
from helper_c34 import AES128CBC, Generator, SHA1, mod_pow

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
        
    def get_public_key(self):
        return self.public_key
        
    def set_shared_secret_key(self, other_party_public_key):
        self.shared_secret_key = mod_pow(other_party_public_key, self._secret_key, self.p)
        
    def get_shared_secret_key(self):
        return self.shared_secret_key
    
def parameter_injection_attack(Alice: DiffieHellman, alice_message: bytes, Bob: DiffieHellman, bob_message: bytes) -> [bytes]:
    # Step 1: Alice Sends Her Public Key 'A' To Bob (Intercepted By Eva)
    Eva_A = Alice.get_public_key()
    
    # Step 2: Eva Sends 'p' To Bob
    Bob.set_shared_secret_key(Alice.p)
    
    # Step 3: Bob Sends His Public Key 'B' To Alice (Intercepted By Eva)
    Eva_B = Bob.get_public_key()
    
    # Step 4: Eva Sends 'p' To Alice
    Alice.set_shared_secret_key(Bob.p)
    
    # Step 5: Alice Sends Her Encrypted Message To Bob (Intercepted By Eva)
    _key = SHA1(Alice.get_shared_secret_key().to_bytes(1, "big"))[:AES128CBC.block_size]
    _iv = Generator.generate_random_bytes(16, 16)
    _encrypted_message = AES128CBC.encrypt(alice_message, _key, _iv) + _iv
    
    # Step 6: Eva Sends The Encrypted Message To Bob
    
    # Step 7: Bob Sends His Encrypted Response To Alice (Intercepted By Eva)
    _key = SHA1(Bob.get_shared_secret_key().to_bytes(1, "big"))[:AES128CBC.block_size]
    _iv = Generator.generate_random_bytes(16, 16)
    _encrypted_response = AES128CBC.encrypt(bob_message, _key, _iv) + _iv
    
    # Step 8: Eva Sends The Encrypted Reponse To Alice
    
    # Get Secret Key For AES
    mitm_key = SHA1(b"\x00")[:AES128CBC.block_size]
    
    # Get Alice's And Bob's IVs
    mitm_alice_iv = _encrypted_message[-AES128CBC.block_size:]
    mitm_bob_iv = _encrypted_response[-AES128CBC.block_size:]
    
    # Decrypt Alice's And Bob's Messagess
    mitm_alice_decrypted = AES128CBC.decrypt(_encrypted_message[:-AES128CBC.block_size], mitm_key, mitm_alice_iv)
    mitm_bob_decrypted = AES128CBC.decrypt(_encrypted_response[:-AES128CBC.block_size], mitm_key, mitm_bob_iv)
    
    return mitm_alice_decrypted, mitm_bob_decrypted
    
def c34(Alice: DiffieHellman, alice_message: bytes, Bob: DiffieHellman, bob_message: bytes) -> [bytes]:
    return parameter_injection_attack(Alice, alice_message, Bob, bob_message)