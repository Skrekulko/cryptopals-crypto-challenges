#
#   02 - Fixed XOR
#

class XOR:
    @staticmethod
    def fixed_xor(byte_string1: bytes, byte_string2: bytes) -> bytes:
        if len(byte_string1) == len(byte_string2):
            return bytes(a ^ b for (a, b) in zip(byte_string1, byte_string2))
        else:
            raise ValueError
