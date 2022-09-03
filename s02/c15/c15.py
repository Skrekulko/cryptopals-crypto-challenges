#
#   15 - PKCS#7 padding validation
#

class PKCS7:
    @staticmethod
    def padding(input: bytes, block_size: int) -> bytes:
        padding_length = block_size - (len(input) % block_size)
        
        if padding_length == block_size:
            return input
        
        return input + padding_length * padding_length.to_bytes(1, "big")
        
    @staticmethod
    def strip(input: bytes) -> bytes:
        last_byte = input[-1]
        
        if input[-last_byte:] != last_byte * last_byte.to_bytes(1, "big"):
            raise ValueError("Incorrect padding.")
        
        return input[:-last_byte]

def c15(input):
    return PKCS7.strip(input)