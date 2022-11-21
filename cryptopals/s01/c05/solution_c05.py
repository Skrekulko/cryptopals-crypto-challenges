#
#   05 - Implement repeating-key XOR
#

class XOR:
    @staticmethod
    def fixed_xor(byte_string1: bytes, byte_string2: bytes) -> bytes:
        if len(byte_string1) == len(byte_string2):
            return bytes(a ^ b for (a, b) in zip(byte_string1, byte_string2))
        else:
            raise ValueError

    @staticmethod
    def repeating_key_xor(byte_string: bytes, key: bytes) -> bytes:
        # Calculate The Total Amount Of Needed Repetitions
        repetitions = 1 + (len(byte_string) // len(key))

        # Construct The Repeated Secret Key
        key = (key * repetitions)[:len(byte_string)]

        # Do A Fixed XOR
        return XOR.fixed_xor(byte_string, key)