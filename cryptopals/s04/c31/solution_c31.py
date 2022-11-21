#
#   31 - Implement and break HMAC-SHA1 with an artificial timing leak
#

import requests
from statistics import median


class Decipher:
    @staticmethod
    def hmac_next_byte(known_bytes: bytes, text: bytes, hmac_size: int, rounds: int) -> bytes:
        # Array For Counting The Request Time For Every Possible Byte
        times = [[] for _ in range(256)]

        # Suffix Size
        suffix_size = hmac_size - len(known_bytes)

        # Performing Multiple Rounds For Better Statistical Evidence
        for _ in range(rounds):
            # Every Possible Character
            for i in range(256):
                suffix = i.to_bytes(1, "big") + (suffix_size - 1) * b"\x00"
                signature = known_bytes + suffix

                response = requests.get(f"http://127.0.0.1:8082/test?file={text.hex()}&signature={signature.hex()}")

                # In Case The Correct Signature Was Found Already
                if response.status_code == 200:
                    return suffix

                times[i].append(response.elapsed.total_seconds())

        # Median Time
        median_times = [median(bytes_times) for bytes_times in times]

        # Get The Highest Median Time Byte
        best = max(range(256), key=lambda b: median_times[b])

        return best.to_bytes(1, "big")

    @staticmethod
    def hmac_timing_attack(text: bytes, hmac_size: int, rounds: int, max_hmac_bytes=None) -> bytes:
        # Known Bytes Of HMAC
        known_bytes = b""

        # Discover HMAC Bytes For HMAC Length
        while len(known_bytes) < hmac_size:
            # Testing Purposes
            if max_hmac_bytes is not None and len(known_bytes) >= max_hmac_bytes:
                return known_bytes
            known_bytes += Decipher.hmac_next_byte(known_bytes, text, hmac_size, rounds)

        # Check Final HMAC
        response = requests.get(f"http://127.0.0.1:8082/test?file={text.hex()}&signature={known_bytes.hex()}")

        if response.status_code == 200:
            return known_bytes
        else:
            raise Exception("Unable to correctly guess the HMAC!")
