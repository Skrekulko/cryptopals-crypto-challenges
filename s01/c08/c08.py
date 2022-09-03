#
#   08 - Detect AES in ECB mode
#

from helper_c08 import load_data

def detect_repeated_blocks(input: bytes, block_size: int) -> bool:
    n_blocks = int(len(input) / block_size)
    blocks = list((input[i * block_size : i * block_size + block_size]) for i in range(n_blocks))
    
    if len(set(blocks)) != n_blocks:
        return True
    else:
        return False

def c08(file_name):
    return detect_repeated_blocks(load_data(file_name), 16)
        