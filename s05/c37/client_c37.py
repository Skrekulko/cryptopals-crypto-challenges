#! /usr/bin/env python

#
#   37 - Break SRP with a zero key
#

import json
from requests import post, get
from random import randint
from Crypto.Util import number
from Crypto.Hash import SHA256
from helper_c37 import SHA1, mod_pow

# SRP Address
srp_address = "http://127.0.0.1:8082/"

# Convert An Integer To Bytes
def int_to_bytes(integer: int) -> bytes:
    integer_len = (max(integer.bit_length(), 1) + 7) // 8
    integer_bytes = integer.to_bytes(integer_len, "big")
    
    return integer_bytes

# RFC5054 Padding
def PAD(integer: int, N: int) -> bytes:
    integer_bytes = int_to_bytes(integer)
    N_bytes = int_to_bytes(N)
    
    padding_len = len(N_bytes) - len(integer_bytes)
    
    return b"\x00" * padding_len + integer_bytes

def client_c37(A = None) -> None:
    # Username And Password
    I = int.from_bytes(b"username", "big")
    P = int.from_bytes(b"password", "big")

    # Send Username 'I'
    response = post(
        srp_address,
        json = {
            "I": I,
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
    a = randint(0, N - 1)
    
    # Public Ephemeral Key 'A'
    if A == None:
        A = mod_pow(g, a, N)
    
    # Calculate Random Scrambling Parameter 'u'
    u = int.from_bytes(SHA1(
        PAD(A, N)
        + PAD(B, N)
    ), "big")
    
    # Multiplier Parameter
    k = int.from_bytes(SHA1(
        int_to_bytes(N) + PAD(g, N)
    ), "big")
    
    # Private Key 'x'
    x = int.from_bytes(SHA1(
        int_to_bytes(s)
        + SHA1(
            int_to_bytes(I)
            + b":"
            + int_to_bytes(P)
        )
    ), "big")

    # Send Public Ephemeral Key 'A'
    response = post(
        srp_address,
        json = {
            "A": A,
        }
    )
    
    # Verify Response Status Code
    if response.status_code != 200:
        raise Exception(f"{response.status_code}: {response.reason}")
    
    # Premaster Secret 'S'
    S = mod_pow(B - k * mod_pow(g, x, N), (a + u * x), N)
    
    # HMAC 1
    M1 = int.from_bytes(
        SHA1(
            int_to_bytes(A)
            + int_to_bytes(B)
            + int_to_bytes(S)
        ), "big"
    )
    
    # Send HMAC 1
    response = post(
        srp_address,
        json = {
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
        SHA1(
            int_to_bytes(A)
            + int_to_bytes(M1)
            + int_to_bytes(S)
        ), "big"
    ):
        raise Exception("Could not verify HMAC 2!")
        
    # Session Key 'K'
    K = int.from_bytes(
        SHA1(int_to_bytes(S)), "big"
    )
    
    return K
    
if __name__ == "__main__":
    client_c37()
