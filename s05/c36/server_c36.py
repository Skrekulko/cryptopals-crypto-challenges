#! /usr/bin/env python

#
#   36 - Implement Secure Remote Password (SRP)
#

from flask import Flask, request, jsonify, json
from random import randint
from helper_c36 import SHA1, mod_pow

# Flask
app = Flask(__name__)

# JSON File Containing Agreed Values
file_name = "agreed_values.json"

# Load Agreed Values From JSON File
def load_agreed_values() -> None:
    global N, g, I, P

    try:
        with open(file_name, "r") as file:
            agreed_values = json.load(file)
            N = agreed_values["N"]  # Large Safe Prime
            g = agreed_values["g"]  # Generator Modulo N
            I = agreed_values["I"]  # Username
            P = agreed_values["P"]  # Cleartext Password
    except FileNotFoundError:
        write_agreed_values()
        load_agreed_values()
        
# Write Agreed Values Into A JSON File
def write_agreed_values() -> None:
    agreed_values = {
        "N": 0x9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB,                            #Large Safe Prime
        "g": 2,                     # Generator Modulo N
        "I": 8463219666911849829,   # Username
        "P": 8097880544751088228,   # Cleartext Password
    }
    
    with open(file_name, "w") as file:
        json_object = json.dump(agreed_values, file, indent = 4)

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

# Session Key 'K'
@app.route("/session_key")
def session_key():
    return jsonify(K = K)

# SRP
@app.route("/", methods=["POST"])
def login():
    global s, A, B, K, v, u, b, S
    
    # POST Request Only
    if request.method == "POST":
        # Get Post Data In JSON Format
        post_data = request.get_json()
    
        if "I" in post_data:
            # Salt
            s = randint(0, (1 << 32) - 1)
            
            # Private Ephemeral Key 'b'
            b = randint(0, N - 1)
            
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
            
            # Password Verifier
            v = mod_pow(g, x, N)
            
            # Public Ephemeral Key 'B'
            B = k * v + mod_pow(g, b, N)
            
            # Send Large Safe Prime 'N', Generator Modulo N 'g', Salt 's' And Public Ephemeral Key 'B'
            return jsonify(N = N, g = g, s = s, B = B)
        elif "A" in post_data:
            # Get Public Ephemeral Key 'A'
            A = post_data.get("A")
            
            # Random Scrambling Parameter 'u'
            u = int.from_bytes(SHA1(
                PAD(A, N)
                + PAD(B, N)
            ), "big")
            
            # Premaster Secret 'S'
            S = mod_pow(A * mod_pow(v, u, N), b, N)
            
            return "OK", 200
        elif "M1" in post_data:
            # Get HMAC 1
            M1 = post_data.get("M1")
        
            # Verify HMAC 1
            if M1 != int.from_bytes(
                SHA1(
                    int_to_bytes(A)
                    + int_to_bytes(B)
                    + int_to_bytes(S)
                ), "big"
            ):
                return "Could not verify HMAC 1!", 500
                
            # HMAC 2
            M2 = int.from_bytes(
                SHA1(
                    int_to_bytes(A)
                    + int_to_bytes(M1)
                    + int_to_bytes(S)
                ), "big"
            )
            
            # Session Key 'K'
            K = int.from_bytes(
                SHA1(int_to_bytes(S)), "big"
            )
            
            return jsonify(M2 = M2)

def main():
    load_agreed_values()
    app.run(port = 8082)

if __name__ == "__main__":
    main()
    