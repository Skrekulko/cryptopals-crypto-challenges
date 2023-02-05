#
#   42 - Bleichenbacher's e=3 RSA Attack
#

import re
from cryptopals.asymmetric import RSA
from cryptopals.hash import SHA1
from cryptopals.utils import Converter


class Math:
    @staticmethod
    def root_binary(x, n):
        # Initial Guess
        guess = 1

        # Counter For Steps
        step = 1

        while True:
            w = (guess + step) ** n
            if w == x:
                return (guess + step,) * 2
            elif w < x:
                step <<= 1
            elif step == 1:
                return guess, guess + 1
            else:
                guess += step >> 1
                step = 1


class Oracle(RSA):
    def __init__(self, bits=2048, e=65537) -> None:
        # Initialize RSA
        super().__init__(bits=bits, e=e)

        # Hashes Of Ciphertexts (Empty)
        self.hashes = []

        # Default Plaintext
        self.plaintext = Converter.hex_to_int(hexadecimal=b"armoring", byteorder="big")

        # Default Ciphertext
        self.ciphertext = self.encrypt(message=self.plaintext)

        # Default Hash Of The Ciphertext (For Testing Purposes)
        self.hashes.append(SHA1.digest(m=Converter.int_to_hex(integer=self.ciphertext)))

    def emsa_pkcs1_v1_5_encoding(self, message: int) -> int:
        # Private Key Size (octets)
        emLen = self.parameters.size_in_bits() // 8

        # Data Digest
        H = SHA1.digest(m=Converter.int_to_hex(integer=message))

        # Algorithm Identifier
        AI = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"

        # Digest Info
        T = AI + H

        # Digest Info Size (octets)
        tLen = len(T)

        # Message Size Check
        if emLen < tLen + 11:
            raise Exception("intended encoded message length too short")

        # Padding
        PS = (emLen - tLen - 3) * b"\xff"

        # Encoded Message
        EM = b"\x00" + b"\x01" + PS + b"\x00" + T

        return EM

    def sign(self, message: int) -> int:
        # Encoded Message
        EM = self.emsa_pkcs1_v1_5_encoding(message=message)

        # Sign The Message
        return super().sign(message=EM)

    def verify(self, signature: bytes, message: bytes) -> bool:
        # Encrypt The Signature To Get The Original Encoded Message
        # And Prepend '\x00' Byte (Since It Was Lost Due To Being A Null)
        EM1 = b"\x00" + Converter.int_to_hex(
            integer=self.encrypt(
                message=Converter.hex_to_int(
                    hexadecimal=signature,
                    byteorder="big"
                )
            )
        )

        # Verify The Signature (Block In PKCS1.5 Standard Format)
        r = re.compile(b"\x00\x01\xff+?\x00.{15}(.{20})", re.DOTALL)

        # Check If The Encoding Format Matches
        m = r.match(EM1)

        # No Match At All
        if not m:
            return False

        # Get The Hash
        data_hash = m.group(1)

        # Compare
        return data_hash == SHA1.digest(m=message)


def bleichenbacher_signature(n_size: int, e: int, message: bytes) -> bytes:
    # Composite n Size Condition
    if n_size < 369:
        raise Exception("Composite n must be at least 369 bits large.")

    # Pre-Forged Signature
    preforged_signature = Converter.hex_to_int(
        hexadecimal=(
            b"\x00\x01" + Converter.int_to_hex(
            integer=(
                pow(2, 192) -
                pow(2, 128) +
                Converter.hex_to_int(
                    hexadecimal=b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
                    byteorder="big"
                )) * pow(2, n_size - 208) +
                Converter.hex_to_int(
                    hexadecimal=SHA1.digest(m=message),
                    byteorder="big"
                ) * pow(2, n_size - 368)
             )
        ), byteorder="big"
    )

    # Forged Signature (e-th Root of Pre-Forged Signature)
    forged_signature = Math.root_binary(preforged_signature, e)[1]

    return Converter.int_to_hex(integer=forged_signature)
