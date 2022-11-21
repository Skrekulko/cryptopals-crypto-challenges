#! /usr/bin/env python

#
#   37 - Break SRP with a zero key
#

from flask import Flask, request, jsonify, json
from cryptopals.converter import Converter
from cryptopals.hash import SHA1
from cryptopals.utils import Math, Generator

global N, g, username, password
global s, A, B, K, v, u, b, S

# Flask
app = Flask(__name__)

# JSON File Containing Agreed Values
file_name = "agreed_values.json"


# Load Agreed Values From JSON File
def load_agreed_values() -> None:
    global N, g, username, password

    try:
        with open(file_name, "r") as file:
            agreed_values = json.load(file)
            N = agreed_values["N"]  # Large Safe Prime
            g = agreed_values["g"]  # Generator Modulo N
            username = agreed_values["I"]  # Username
            password = agreed_values["P"]  # Plaintext Password
    except FileNotFoundError:
        raise FileNotFoundError


# RFC5054 Padding
def pad(integer: int, n: int) -> bytes:
    integer_bytes = Converter.int_to_hex(integer)
    N_bytes = Converter.int_to_hex(n)
    
    padding_len = len(N_bytes) - len(integer_bytes)
    
    return b"\x00" * padding_len + integer_bytes


# Session Key 'K'
@app.route("/session_key")
def session_key():
    return jsonify(K=K)


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
            s = Generator.random_int(0, (1 << 32) - 1)
            
            # Private Ephemeral Key 'b'
            b = Generator.random_int(0, N - 1)
            
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
            
            # Password Verifier
            v = Math.mod_pow(g, x, N)
            
            # Public Ephemeral Key 'B'
            B = k * v + Math.mod_pow(g, b, N)
            
            # Send Large Safe Prime 'N', Generator Modulo N 'g', Salt 's' And Public Ephemeral Key 'B'
            return jsonify(N=N, g=g,  s=s, B=B)
        elif "A" in post_data:
            # Get Public Ephemeral Key 'A'
            A = post_data.get("A")
            
            # Random Scrambling Parameter 'u'
            u = int.from_bytes(SHA1.digest(
                m=pad(A, N)
                + pad(B, N)
            ), "big")
            
            # Premaster Secret 'S'
            S = Math.mod_pow(A * Math.mod_pow(v, u, N), b, N)
            
            return "OK", 200
        elif "M1" in post_data:
            # Get HMAC 1
            M1 = post_data.get("M1")
        
            # Verify HMAC 1
            if M1 != int.from_bytes(
                SHA1.digest(
                    m=Converter.int_to_hex(A)
                    + Converter.int_to_hex(B)
                    + Converter.int_to_hex(S)
                ), "big"
            ):
                return "Could not verify HMAC 1!", 500
                
            # HMAC 2
            M2 = int.from_bytes(
                SHA1.digest(
                    m=Converter.int_to_hex(A)
                    + Converter.int_to_hex(M1)
                    + Converter.int_to_hex(S)
                ), "big"
            )
            
            # Session Key 'K'
            K = int.from_bytes(
                SHA1.digest(Converter.int_to_hex(S)), "big"
            )
            
            return jsonify(M2=M2)


def main():
    load_agreed_values()
    app.run(port=8082)


if __name__ == "__main__":
    main()
    