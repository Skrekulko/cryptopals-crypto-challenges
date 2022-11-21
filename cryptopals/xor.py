class XOR:
    @staticmethod
    def fixed(byte_string1: bytes, byte_string2: bytes) -> bytes:
        if len(byte_string1) == len(byte_string2):
            return bytes(a ^ b for (a, b) in zip(byte_string1, byte_string2))
        else:
            raise ValueError

    @staticmethod
    def repeating(byte_string: bytes, repeating_byte_string: bytes) -> bytes:
        # Calculate The Total Amount Of Needed Repetitions
        repetitions = 1 + (len(byte_string) // len(repeating_byte_string))

        # Construct The Repeated Byte String
        repeating_byte_string = (repeating_byte_string * repetitions)[:len(byte_string)]

        # Do A Fixed XOR
        return XOR.fixed(byte_string, repeating_byte_string)

    @staticmethod
    def single_byte(byte_string: bytes, key: int) -> bytes:
        return bytes((byte ^ key) for byte in byte_string)
