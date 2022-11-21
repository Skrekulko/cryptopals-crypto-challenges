#! /usr/bin/env python

#
#   36 - Implement Secure Remote Password (SRP)
#

from requests import post
from cryptopals.Generator import Generator
from cryptopals.utils import Math
from cryptopals.hash import SHA1

# SRP Address
srp_address = "http://127.0.0.1:8082/"


# Convert An Integer To Bytes
def int_to_bytes(integer: int) -> bytes:
    integer_len = (max(integer.bit_length(), 1) + 7) // 8
    integer_bytes = integer.to_bytes(integer_len, "big")
    
    return integer_bytes


# RFC5054 Padding
def pad(integer: int, n: int) -> bytes:
    integer_bytes = int_to_bytes(integer)
    N_bytes = int_to_bytes(n)
    
    padding_len = len(N_bytes) - len(integer_bytes)
    
    return b"\x00" * padding_len + integer_bytes


def client_c36() -> int:
    # Username And Password
    username = int.from_bytes(b"username", "big")
    password = int.from_bytes(b"password", "big")

    # Send Username 'username'
    response = post(
        srp_address,
        json={
            "username": username,
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
    A = Math.mod_pow(g, a, N)
    
    # Calculate Random Scrambling Parameter 'u'
    u = int.from_bytes(SHA1.digest(
        m=pad(A, N)
        + pad(B, N)
    ), "big")
    
    # Multiplier Parameter
    k = int.from_bytes(SHA1.digest(
        m=int_to_bytes(N) + pad(g, N)
    ), "big")
    
    # Private Key 'x'
    x = int.from_bytes(SHA1.digest(
        m=int_to_bytes(s)
        + SHA1.digest(
            m=int_to_bytes(username)
            + b":"
            + int_to_bytes(password)
        )
    ), "big")

    # Send Public Ephemeral Key 'A'
    response = post(
        srp_address,
        json={
            "A": A,
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
            m=int_to_bytes(A)
            + int_to_bytes(B)
            + int_to_bytes(S)
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
            m=int_to_bytes(A)
            + int_to_bytes(M1)
            + int_to_bytes(S)
        ), "big"
    ):
        raise Exception("Could not verify HMAC 2!")
        
    # Session Key 'K'
    K = int.from_bytes(
        SHA1.digest(m=int_to_bytes(S)), "big"
    )
    
    return K


if __name__ == "__main__":
    client_c36()
