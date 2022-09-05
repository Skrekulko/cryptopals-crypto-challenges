#
#   02 - Fixed XOR
#

def fixed_xor(input1: bytes, input2: bytes) -> bytes:
    if len(input1) == len(input2):
        return bytes(a ^ b for (a, b) in zip(input1, input2))
    else:
        raise ValueError

#
#   06 - Break repeating-key XOR
#

import codecs

def load_data(file_name: str) -> bytes:
    with open(file_name) as file:
        data = file.read()
        data = codecs.decode(bytes(data.encode("ascii")), "base64")
        return data

#
#   07 - AES in ECB mode
#

def pkcs7_unpadding(input: bytes) -> bytes:
    last_byte = input[-1]
    if input[-last_byte:] == last_byte * last_byte.to_bytes(1, "big"):
        return input[:-last_byte]
    else:
        return input
