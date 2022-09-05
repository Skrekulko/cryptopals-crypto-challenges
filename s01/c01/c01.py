#
#   01 - Convert hex to base64
#

import codecs

def convert_hex_to_base64(input: bytes) -> bytes:
    return codecs.encode(codecs.decode(input, "hex"), "base64").rstrip()

def c01(input):
    return convert_hex_to_base64(input)
