import codecs


class Converter:
    @staticmethod
    def hex_to_base64(hex_bytes: bytes) -> bytes:
        return codecs.encode(codecs.decode(hex_bytes, "hex"), "base64").rstrip()

    @staticmethod
    def base64_to_hex(base64_bytes: bytes) -> bytes:
        return codecs.decode(base64_bytes, "base64")

    @staticmethod
    def int_to_hex(integer: int) -> bytes:
        integer_len = (max(integer.bit_length(), 1) + 7) // 8
        return integer.to_bytes(integer_len, "big")
