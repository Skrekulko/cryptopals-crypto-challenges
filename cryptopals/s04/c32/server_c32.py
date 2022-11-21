#! /usr/bin/env python

#
#   32 - Break HMAC-SHA1 with a slightly less artificial timing leak
#

from flask import Flask, request
from time import sleep
from cryptopals.hash import SHA1
from cryptopals.XOR import XOR
from cryptopals.Generator import Generator


class MySHA1(SHA1):
    @staticmethod
    def hmac(k: bytes, text: bytes) -> bytes:
        # SHA-1 Block Size
        B = 64

        # Key Length
        K_len = len(k)

        # ipad, opad
        ipad, opad = b"\x36" * B, b"\x5c" * B

        if K_len == B:
            K0 = k
        else:
            if K_len > B:
                L = SHA1.digest(k)
                L_len = len(L)
                # K0 = H(K) || (B - L) * 00 .. 00
                K0 = L + (B - L_len) * b"\x00"
            else:
                # K0 = (B - K) * 00 .. 00
                K0 = k + (B - K_len) * b"\x00"

        # 'H((K0 + opad) || H((K0 + ipad) || text))'
        return SHA1.digest(XOR.fixed(K0, opad) + SHA1.digest(XOR.fixed(K0, ipad) + text))


def insecure_compare(digest: bytes, signature: bytes) -> bool:
    for byte1, byte2 in zip(digest, signature):
        # Not Equal
        if byte1 != byte2:
            return False

        # Sleep For 'delay' Time
        sleep(delay)

    return True


app = Flask(__name__)

# Insecure Compare Delay
delay = 0.005

# Randomly Generated 128-Bit Key
server_key = Generator.key_128b()


# Get Server Key (Testing Purposes)
@app.route("/key", methods=["GET"])
def get_key() -> [str, int]:
    if request.method == "GET":
        return server_key.hex(), 200


# Check HMAC Of File And Its Signature
@app.route("/test", methods=["GET"])
def test() -> [str, int]:
    if request.method == "GET":
        filename = bytes.fromhex(request.args.get("file"))
        digest = MySHA1.hmac(server_key, filename)
        signature = bytes.fromhex(request.args.get("signature"))

        # Check Using The Insecure Compare Function
        if insecure_compare(digest, signature):
            return "Correct HMAC.", 200
        else:
            return "Incorrect HMAC!", 500


def main():
    app.run(port=8082)


if __name__ == "__main__":
    main()
