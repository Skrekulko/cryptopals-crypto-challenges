#
#   48 - Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)
#


import re
from collections import namedtuple
from random import randint
from Crypto.Random import get_random_bytes
from cryptopals.asymmetric import RSA
from cryptopals.utils import Converter, Math


Interval = namedtuple("Interval", ["lower_bound", "upper_bound"])


class Oracle(RSA):
    def __init__(self, bits=2048, e=65537) -> None:
        # Initialize RSA
        super().__init__(bits=bits, e=e)

    def encode(self, message: bytes) -> bytes:
        # Message Length
        message_length = len(message)

        # Check Message Length
        if message_length > self.parameters.size_in_bytes() - 11:
            raise Exception("Wrong message length.")

        # Check Padding String Length And Null Byte
        padding_string_length = self.parameters.size_in_bytes() - message_length - 3
        if not padding_string_length >= 8:
            raise Exception("Wrong padding string length.")

        # Padding String (PS)
        while True:
            padding_string = get_random_bytes(padding_string_length)

            # Check Padding String For Null Byte
            if b"\x00" not in padding_string:
                break

        # Encoded Message (EM)
        encoded_message = b"\x00\x02" + padding_string + b"\x00" + message

        return encoded_message

    def decode(self, message: bytes) -> bytes:
        # Check Encoded Message Length
        if len(message) != self.parameters.size_in_bytes():
            raise Exception("Wrong encoded message length.")

        # Parse The Encoded Message
        r = re.compile(b"(\x00\x02)(.+)\x00(.+)", re.DOTALL)
        m = r.match(message)

        # No Match At All
        if not m:
            raise Exception("No match found.")

        # Check The Groups
        if m.group(1) != b"\x00\x02" or len(m.group(2)) < 8:
            raise Exception("Groups did not match.")

        return m.group(3)

    def encrypt(self, message: bytes) -> bytes:
        # Encoded Message (EM)
        encoded_message = self.encode(message=message)

        # Encrypt The Encoded Message
        return Converter.int_to_hex(
            integer=super().encrypt(
                message=Converter.hex_to_int(
                    hexadecimal=encoded_message,
                    byteorder="big"
                )
            )
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        # Check Ciphertext Length
        if len(ciphertext) != self.parameters.size_in_bytes() or self.parameters.size_in_bytes() < 11:
            raise Exception(1, "Wrong ciphertext length.")

        # Encoded Message
        encoded_message = b"\x00" + Converter.int_to_hex(
            integer=super().decrypt(
                message=Converter.hex_to_int(
                    hexadecimal=ciphertext,
                    byteorder="big"
                )
            )
        )

        # Simple PKCS Conformity Check
        if len(encoded_message) == self.parameters.size_in_bytes() and encoded_message[:2] == b"\x00\x02":
            return encoded_message
        else:
            raise Exception("Not PKCS conforming.")


def floor(a: int, b: int) -> int:
    return a // b


def ceil(a: int, b: int) -> int:
    return a // b + (a % b > 0)


def bleichenbacher_chosen_plaintext(oracle: Oracle, ciphertext: bytes, conforming=True) -> bytes:
    # Oracle's Parameters
    n = oracle.parameters.n
    n_size = oracle.parameters.size_in_bytes()
    e = oracle.parameters.e

    # Initial Parameters
    c = Converter.hex_to_int(hexadecimal=ciphertext, byteorder="big")
    B = 2 ** (8 * (n_size - 2))
    intervals = [Interval(2 * B, 3 * B - 1)]

    # Step 1: Blinding (Only If Ciphertext Is Not PKCS Conforming)
    if not conforming:
        s = step_1(oracle=oracle, n=n, e=e, c=c)
    else:
        s = 1

    # Step 2.a: Starting The Search
    s = step_2a(oracle=oracle, n=n, e=e, c=c, l=ceil(n, 3 * B))

    # Step 3: Narrowing The Set Of Solutions
    intervals = step_3(n=n, b_range=B, s=s, intervals=intervals)

    while True:
        # Step 2.c: Searching With One Interval Left
        if len(intervals) >= 2:
            s = step_2a(oracle=oracle, n=n, e=e, c=c, l=s)
        elif len(intervals) == 1:
            a, b = intervals[0]

            # Step 4: Computing The Solution
            if a == b:
                return b"\x00" + Converter.int_to_hex(integer=a % n)

            # Step 2.c: Searching With One Interval Left
            s = step_2c(oracle=oracle, n=n, e=e, c=c, a=a, b=b, prev_s=s, b_range=B)

        # Step 3: Narrowing The Set Of Solutions
        intervals = step_3(n=n, b_range=B, s=s, intervals=intervals)


# Step 1: Blinding
def step_1(oracle: Oracle, n: int, e: int, c: int) -> int:
    while True:
        # Generate Random Number 's'
        s = randint(0, n - 1)

        # Compute Ciphertext 'c_unknown'
        c_unknown = (c * Math.mod_pow(b=s, e=e, m=n)) % n

        # Check For PKCS Conformity
        try:
            oracle.decrypt(ciphertext=Converter.int_to_hex(integer=c_unknown))
            return s
        except (Exception, ):
            pass


# Step 2.a: Starting The Search
def step_2a(oracle: Oracle, n: int, e: int, c: int, l: int) -> int:
    # Lower Bound
    s = l

    while True:
        # Compute Ciphertext 'c_unknown'
        c_unknown = (c * Math.mod_pow(b=s, e=e, m=n)) % n

        # Check For PKCS Conformity
        try:
            oracle.decrypt(ciphertext=Converter.int_to_hex(integer=c_unknown))
            return s
        except (Exception,):
            s += 1


# Step 2.c: Searching With One Interval Left
def step_2c(oracle: Oracle, n: int, e: int, c: int, a: int, b: int, prev_s: int, b_range: int) -> int:
    ri = ceil(2 * (b * prev_s - 2 * b_range), n)

    while True:
        si_lower = ceil(2 * b_range + ri * n, b)
        si_upper = ceil(3 * b_range + ri * n, a)

        for si in range(si_lower, si_upper):
            # Compute Ciphertext 'c_unknown'
            c_unknown = (c * Math.mod_pow(b=si, e=e, m=n)) % n

            # Check For PKCS Conformity
            try:
                oracle.decrypt(ciphertext=Converter.int_to_hex(integer=c_unknown))
                return si
            except (Exception,):
                pass

        # Increment 'ri' By One
        ri += 1


# Step 3: Narrowing The Set Of Solutions
def step_3(n: int, b_range: int, s: int, intervals: [Interval]) -> [Interval]:
    intervals_new = []

    for a, b in intervals:
        r_lower = ceil(a * s - 3 * b_range + 1, n)
        r_upper = ceil(b * s - 2 * b_range, n)

        for r in range(r_lower, r_upper):
            lower_bound = max(a, ceil(2 * b_range + r * n, s))
            upper_bound = min(b, floor(3 * b_range - 1 + r * n, s))

            interval = Interval(lower_bound, upper_bound)

            intervals_new = insert_interval(intervals_new, interval)

    intervals.clear()

    return intervals_new


def insert_interval(intervals: [Interval], interval: Interval) -> [Interval]:
    for i, (a, b) in enumerate(intervals):
        # Construct The Larger Interval If There Are Any Overlaps
        if b >= interval.lower_bound and a <= interval.upper_bound:
            lower_bound = interval.lower_bound
            upper_bound = interval.upper_bound

            intervals[i] = Interval(lower_bound, upper_bound)

            return intervals

    # Insert The New Interval If There Are No Overlaps
    intervals.append(interval)

    return intervals
