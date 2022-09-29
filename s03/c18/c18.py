#
#   18 - Implement CTR, the stream cipher mode
#

from helper_c18 import repeating_key_xor
from math import ceil
from Crypto.Cipher import AES

class AES128CTR:
    block_size = 16

    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce

    def transform(self, input: bytes) -> bytes:
        # Counter
        counter = 0
        
        # Parse The Input Into Blocks
        n_blocks = ceil(len(input) / AES128CTR.block_size)
        in_blocks = list((input[i * AES128CTR.block_size : i * AES128CTR.block_size + AES128CTR.block_size]) for i in range(n_blocks)) 
        
        out_blocks = []
        
        # Transform Each Block
        for block in in_blocks:
            # Construct A Keystream
            keystream_block = AES.new(self.key, AES.MODE_ECB).encrypt(
                self.nonce.to_bytes(AES128CTR.block_size // 2, "little")
                +
                counter.to_bytes(AES128CTR.block_size // 2, "little")
            )
            
            # XOR The Keystream Block With The Input Block
            encrypted_block = repeating_key_xor(block, keystream_block)
            out_blocks.append(encrypted_block)
            
            # Increment The Counter
            counter += 1
            
        return b"".join(out_blocks)

def c18(input: bytes, key: bytes, nonce: int) -> bytes:
    ctr = AES128CTR(key, nonce)
    
    return ctr.transform(input)