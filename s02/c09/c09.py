#
#   09 - Implement PKCS#7 padding
#

def pkcs7_padding(input: bytes, block_size: int) -> bytes:
    len_input = len(input)
    len_padding = block_size - (len_input % block_size)
    
    if len_padding == block_size:
        return input
    
    padding = len_padding * len_padding.to_bytes(1, "big")
    
    padded_input = input + padding
    
    return padded_input

def c09(input, block_size):
    return pkcs7_padding(input, block_size)