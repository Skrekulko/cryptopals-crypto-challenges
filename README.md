# The Cryptopals Crypto Challenges
### What It is

The cryptopals challenges (https://cryptopals.com/) are a set of practical cryptography exercises that simulate real-world crypto attacks. They're derived from weaknesses in real-world systems and modern cryptographic constructions.

### What's The Purpose Of This Project

The following is my walkthrough of these challenges using the Python 3.10, although only the solution is provided without a detailed explanation (might be added later on), since it should be understandable from the code itself and inserted comments in it.

### Status Of This Project

This is still a work in progress. Since I am not solving the challenges on a regular basis, the update schedule is erratic. In the table of contents, every solved challenge is indicated with a :heavy_check_mark:, while every unsolved challenge is marked with a :x:.

## Solutions

### Naming Format

To make it easier to distinguish the solutions and tests for each solution, a common name format was implemented. The name format for the solutions is:

>s**XX**\_c**YY**

where **XX** represents the number of the set, while **YY** represents the number of the challenge.

### Where To Put Your Solution

The solution for the particular challenge must be included within the corresponding function that returns the result (solution), e.g. solution for challenge _Convert hex to base64_ must be inside of the **s01_c01()** function. Outside of the corresponding function, any code can be written as long as it returns the result (solution) for further testing.

```python
#
#   01 - Convert hex to base64
#

def helper_function(input):
    ...

def s01_c01(input):
    ...

    return solution

```

## How To Run

### Virtual Environment

Python virtual environment is recommended for running these challenges, with a small guide on how to set it up here:

#### Installation And Activation

```shell
# Install virtualenv If Not Already Installed
$ pip3 install virtualenv

# Create The Virtual Environment
$ python3 -m virtualenv -p python3 venv

# Activate The Virtual Environment
source venv/bin/activate
```

#### Deactivation

```shell
# Deactivate The Virtual Environment After Being Done With The Challenges
deactivate
```

### Tests

For testing, the *pytest* framework is used to compare written solutions to existing solutions of solved challenges. Aside from *pytest*, *pytest-timeout* is used to abort tests when the specified amount of time is exceeded. The timeout is set to 60 seconds by default, which may be increased in the future as the number of solved challenges increases. This timeout can be configured in the *pyproject.toml* file as follows:

```
[tool.pytest.ini_options]
timeout = 60
```

#### Naming Format

The tests have the same naming format as the solutions, with the addition of 'test_' prefix to indicate that they are tests:

>test\_s**XX**\_c**YY**

#### Test Structure

todo:

```python
#
#   01 - Convert hex to base64
#

from solutions import s01_c01
def test_s01_c01() -> None:
    input = b"0123456789abcdef"
    result = b"ASNFZ4mrze8="
    
    assert s01_c01(input) == result
```

#### Running Tests

To run the tests for the solutions, run the pytest command with the verbosity flag:

```bash
$ pytest -v

test_solutions.py::test_s01_c01 PASSED                                                                              [100%]
```

## Table Of Contents
* Set 1: Basics
  1. Convert hex to base64 :heavy_check_mark:
  2. Fixed XOR :heavy_check_mark:
  3. Single-byte XOR cipher :heavy_check_mark:
  4. Detect single-character XOR :heavy_check_mark:
  5. Implement repeating-key XOR :heavy_check_mark:
  6. Break repeating-key XOR :heavy_check_mark:
  7. AES in ECB mode :heavy_check_mark:
  8. Detect AES in ECB mode :heavy_check_mark:
  
* Set 2: Block crypto
  1. Implement PKCS#7 padding :heavy_check_mark:
  2. Implement CBC mode :heavy_check_mark:
  3. An ECB/CBC detection oracle :heavy_check_mark:
  4. Byte-at-a-time ECB decryption (Simple) :heavy_check_mark:
  5. ECB cut-and-paste :heavy_check_mark:
  6. Byte-at-a-time ECB decryption (Harder) :heavy_check_mark:
  7. PKCS#7 padding validation :heavy_check_mark:
  8. CBC bitflipping attacks :x:

* Set 3: Block & stream crypto
  1. The CBC padding oracle :x:
  2. Implement CTR, the stream cipher mode :x:
  3. Break fixed-nonce CTR mode using substitutions :x:
  4. Break fixed-nonce CTR statistically :x:
  5. Implement the MT19937 Mersenne Twister RNG :x:
  6. Crack an MT19937 seed :x:
  7. Clone an MT19937 RNG from its output :x:
  8. Create the MT19937 stream cipher and break it :x:

* Set 4: Stream crypto and randomness
  1. Break "random access read/write" AES CTR :x:
  2. CTR bitflipping :x:
  3. Recover the key from CBC with IV=Key :x:
  4. Implement a SHA-1 keyed MAC :x:
  5. Break a SHA-1 keyed MAC using length extension :x:
  6. Break an MD4 keyed MAC using length extension :x:
  7. Implement and break HMAC-SHA1 with an artificial timing leak :x:
  8. Break HMAC-SHA1 with a slightly less artificial timing leak :x:

* Set 5: Diffie-Hellman and friends
  1. Implement Diffie-Hellman :x:
  2. Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection :x:
  3. Implement DH with negotiated groups, and break with malicious "g" parameters :x:
  4. Implement Secure Remote Password (SRP) :x:
  5. Break SRP with a zero key :x:
  6. Offline dictionary attack on simplified SRP :x:
  7. Implement RSA :x:
  8. Implement an E=3 RSA Broadcast attack :x:

* Set 6: RSA and DSA
  1. Implement unpadded message recovery oracle :x:
  2. Bleichenbacher's e=3 RSA Attack :x:
  3. DSA key recovery from nonce :x:
  4. DSA nonce recovery from repeated nonce :x:
  5. DSA parameter tampering :x:
  6. RSA parity oracle :x: 
  7. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case) :x:
  8. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case) :x:

* Set 7: Hashes
  1. CBC-MAC Message Forgery :x:
  2. Hashing with CBC-MAC :x:
  3. Compression Ratio Side-Channel Attacks :x:
  4. Iterated Hash Function Multicollisions :x:
  5. Kelsey and Schneier's Expandable Messages :x:
  6. Kelsey and Kohno's Nostradamus Attack :x:
  7. MD4 Collisions :x:
  8. RC4 Single-Byte Biases :x:

* Set 8: Abstract Algebra
  1. Diffie-Hellman Revisited: Small Subgroup Confinement :x:
  2. Pollard's Method for Catching Kangaroos :x:
  3. Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks :x:
  4. Single-Coordinate Ladders and Insecure Twists :x:
  5. Duplicate-Signature Key Selection in ECDSA (and RSA) :x:
  6. Key-Recovery Attacks on ECDSA with Biased Nonces :x:
  7. Key-Recovery Attacks on GCM with Repeated Nonces :x:
  8. Key-Recovery Attacks on GCM with a Truncated MAC :x:
  9. Truncated-MAC GCM Revisited: Improving the Key-Recovery Attack via Ciphertext Length Extension :x:
  10. Exploiting Implementation Errors in Diffie-Hellman :x:

## License
Everything in this repository is released under the terms of the MIT License. For more information, please see the file "LICENSE".
