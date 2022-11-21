#! /usr/bin/env python

#
#   37 - Break SRP with a zero key
#

from requests import post
from cryptopals.converter import Converter
from cryptopals.utils import Math
from cryptopals.hash import SHA1
from cryptopals.Generator import Generator

# SRP Address
srp_address = "http://127.0.0.1:8082/"


# RFC5054 Padding
def pad(integer: int, n: int) -> bytes:
    integer_bytes = Converter.int_to_hex(integer)
    N_bytes = Converter.int_to_hex(n)
    
    padding_len = len(N_bytes) - len(integer_bytes)
    
    return b"\x00" * padding_len + integer_bytes


def client_c37(ae=None) -> int:
    # Username And Password
    username = int.from_bytes(b"username", "big")
    password = int.from_bytes(b"password", "big")

    # Send Username 'I'
    response = post(
        srp_address,
        json={
            "I": username,
        }
    )
    
    # Verify Response Status Code
    if response.status_code != 200:
        raise Exception(f"{response.status_code}: {response.reason}")
    
    # Get Large Safe Prime 'N', Generator Modulo N 'g', Salt 's' And Public Ephemeral Key 'B'
    N = response.json().get("N")
    g = response.json().get("g")
    s = response.json().get("s")
    B = response.json().get("B")
    
    # Private Ephemeral Key 'a'
    a = Generator.random_int(0, N - 1)
    
    # Public Ephemeral Key 'A'
    if ae is None:
        ae = Math.mod_pow(g, a, N)
    
    # Calculate Random Scrambling Parameter 'u'
    u = int.from_bytes(SHA1.digest(
        m=pad(ae, N)
        + pad(B, N)
    ), "big")
    
    # Multiplier Parameter
    k = int.from_bytes(SHA1.digest(
        m=Converter.int_to_hex(N) + pad(g, N)
    ), "big")
    
    # Private Key 'x'
    x = int.from_bytes(SHA1.digest(
        m=Converter.int_to_hex(s)
        + SHA1.digest(
            m=Converter.int_to_hex(username)
            + b":"
            + Converter.int_to_hex(password)
        )
    ), "big")

    # Send Public Ephemeral Key 'A'
    response = post(
        srp_address,
        json={
            "A": ae,
        }
    )
    
    # Verify Response Status Code
    if response.status_code != 200:
        raise Exception(f"{response.status_code}: {response.reason}")
    
    # Premaster Secret 'S'
    S = Math.mod_pow(B - k * Math.mod_pow(g, x, N), (a + u * x), N)
    
    # HMAC 1
    M1 = int.from_bytes(
        SHA1.digest(
            m=Converter.int_to_hex(ae)
            + Converter.int_to_hex(B)
            + Converter.int_to_hex(S)
        ), "big"
    )
    
    # Send HMAC 1
    response = post(
        srp_address,
        json={
            "M1": M1
        }
    )
    
    # Verify Response Status Code
    if response.status_code != 200:
        raise Exception(f"{response.status_code}: {response.reason}")
    
    # Get HMAC 2
    M2 = response.json().get("M2")
    
    # Verify HMAC 2
    if M2 != int.from_bytes(
        SHA1.digest(
            m=Converter.int_to_hex(ae)
            + Converter.int_to_hex(M1)
            + Converter.int_to_hex(S)
        ), "big"
    ):
        raise Exception("Could not verify HMAC 2!")
        
    # Session Key 'K'
    K = int.from_bytes(
        SHA1.digest(m=Converter.int_to_hex(S)), "big"
    )
    
    return K


if __name__ == "__main__":
    client_c37()
