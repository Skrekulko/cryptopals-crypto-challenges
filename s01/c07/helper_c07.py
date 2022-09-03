#
#   06 - Break repeating-key XOR
#

import codecs

def load_data(file_name: str) -> bytes:
    with open(file_name) as file:
        data = file.read()
        data = codecs.decode(bytes(data.encode("ascii")), "base64")
        return data
