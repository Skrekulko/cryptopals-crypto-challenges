#
#   01 - Convert hex to base64
#

import codecs


def hex_to_base64(hex_bytes: bytes) -> bytes:
    return codecs.encode(codecs.decode(hex_bytes, "hex"), "base64").rstrip()
