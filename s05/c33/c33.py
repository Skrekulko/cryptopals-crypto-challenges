#
#   33 - Implement Diffie-Hellman
#

from random import randint

# Modular Exponentiation 'a^b mod m'
def mod_pow(b: int, e: int, m: int) -> int:
    x = 1
    
    while e > 0:
        b, e, x = (
            b * b % m,
            e // 2,
            b * x % m if e % 2 else x
        )
    
    return x

# Diffie-Hellman Implementation
class DiffieHellman():
    def __init__(
        self,
        # Generator
        g = 2,
        # Prime
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    ):
        self.g = g
        self.p = p
        # Secret Key
        self._secret_key = randint(0, p - 1)
        self.shared_secret_key = None
        
    def get_public_key(self):
        return mod_pow(self.g, self._secret_key, self.p)
        
    def get_shared_secret_key(self, other_party_public_key):
        if not self.shared_secret_key:
            self.shared_secret_key = mod_pow(other_party_public_key, self._secret_key, self.p)
            
        return self.shared_secret_key

def c33(DH_A: DiffieHellman, DH_B: DiffieHellman) -> bool:
    return DH_A.get_shared_secret_key(DH_B.get_public_key()) == DH_B.get_shared_secret_key(DH_A.get_public_key())