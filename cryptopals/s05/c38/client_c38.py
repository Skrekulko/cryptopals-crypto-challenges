#! /usr/bin/env python

#
#   38 - Offline dictionary attack on simplified SRP
#

from requests import post, get
from cryptopals.utils import Math, Generator, Converter
from cryptopals.hash import SHA1

# SRP Address
srp_address = "http://127.0.0.1:8082/"

# Password Verifier Leak
leak_address = srp_address + "leak"


# RFC5054 Padding
def pad(integer: int, n: int) -> bytes:
    integer_bytes = Converter.int_to_hex(integer)
    N_bytes = Converter.int_to_hex(n)
    
    padding_len = len(N_bytes) - len(integer_bytes)
    
    return b"\x00" * padding_len + integer_bytes


# Brute-Force Password 'P'
def dictionary_attack_password(s: int, username: int, g: int, n: int, v: int) -> int:
    # Dictionary
    with open("/usr/share/dict/words") as dictionary:
        passwords = dictionary.readlines()

    # Try Different Possible Passwords
    for password in passwords:
        # Strip And Encode
        password = password.strip().encode()
        
        # Private Key 'x'
        x = int.from_bytes(SHA1.digest(
            m=Converter.int_to_hex(s)
            + SHA1.digest(
                m=Converter.int_to_hex(username)
                + b":"
                + password
            )
        ), "big")
        
        # Crafted Password Verifier 'v'
        v_crafted = Math.mod_pow(g, x, n)
        
        # Compare The Verifiers
        if v_crafted == v:
            return int.from_bytes(password, "big")
            
    raise Exception("Could not find the password!")


def client_c38(server_address=srp_address) -> int:
    # Username And Password
    username = int.from_bytes(b"username", "big")
    # P = int.from_bytes(b"password", "big")

    # Send Username 'I'
    response = post(
        server_address,
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
    A = Math.mod_pow(g, a, N)
    
    # Calculate Random Scrambling Parameter 'u'
    u = int.from_bytes(SHA1.digest(
        m=pad(A, N)
        + pad(B, N)
    ), "big")
    
    # Get The Leaked Password Verifier 'v'
    response = get(
        leak_address,
    )
    
    # Verify Response Status Code
    if response.status_code != 200:
        raise Exception(f"{response.status_code}: {response.reason}")
    
    # Get The Password 'P'
    P = dictionary_attack_password(s, username, g, N, response.json().get("v"))
    
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
            + Converter.int_to_hex(P)
        )
    ), "big")

    # Send Public Ephemeral Key 'A'
    response = post(
        server_address,
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
            m=Converter.int_to_hex(A)
            + Converter.int_to_hex(B)
            + Converter.int_to_hex(S)
        ), "big"
    )
    
    # Send HMAC 1
    response = post(
        server_address,
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
            m=Converter.int_to_hex(A)
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
    client_c38()
