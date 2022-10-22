#
#   32 - Break HMAC-SHA1 with a slightly less artificial timing leak
#

import requests
from statistics import median

# Known HMAC Length
HMAC_LEN = 20

# Get Next HMAC Byte
def get_next_byte(known_bytes: bytes, filename: bytes, rounds: int) -> bytes:
    # Array For Counting The Request Time For Every Possible Byte
    times = [[] for _ in range(256)]
    
    # Suffix Size
    suffix_size = HMAC_LEN - len(known_bytes)
    
    # Performing Multiple Rounds For Better Statistical Evidence
    for _ in range(rounds):
        # Every Possible Character
        for i in range(256):
            suffix = i.to_bytes(1, "big") + (suffix_size - 1) * b"\x00"
            signature = known_bytes + suffix
            
            response = requests.get(f"http://127.0.0.1:8082/test?file={filename.hex()}&signature={signature.hex()}")
            
            # In Case The Correct Signature Was Found Already
            if response.status_code == 200:
                return suffix
                
            times[i].append(response.elapsed.total_seconds())
            
    # Median Time
    median_times = [median(bytes_times) for bytes_times in times]
    
    # Get The Highest Median Time Byte
    best = max(range(256), key = lambda b: median_times[b])
    
    return best.to_bytes(1, "big")

# HMAC Timing Attack
def hmac_timing_attack(filename: bytes, rounds: int) -> bytes:
    # Known Bytes Of HMAC
    known_bytes = b""
    
    # Discover HMAC Bytes For HMAC Length
    while len(known_bytes) < HMAC_LEN:
        known_bytes += get_next_byte(known_bytes, filename, rounds)
        
    # Check Final HMAC
    response = requests.get(f"http://127.0.0.1:8082/test?file={filename.hex()}&signature={known_bytes.hex()}")
    
    if response.status_code == 200:
        return known_bytes
    else:
        raise Exception("Unable to correctly guess the HMAC!")

def c32(filename: bytes, rounds: int) -> bytes:
    return hmac_timing_attack(filename, rounds)