# The Cryptopals Crypto Challenges
### What It is

The cryptopals challenges (https://cryptopals.com/) are a set of practical cryptography exercises that simulate real-world crypto attacks. They're derived from weaknesses in real-world systems and modern cryptographic constructions.

### What's The Purpose Of This Project

The following is my walkthrough of these challenges using the Python 3.10, although only the solution is provided without a detailed explanation (might be added later on), since it should be understandable from the code itself and inserted comments in it.

### Status Of This Project

This is still a work in progress. Since I am not solving the challenges on a regular basis, the update schedule is erratic. In the table of contents, every solved challenge is indicated with a :heavy_check_mark:, while every unsolved challenge is marked with a :x:.

## Structure Of This Project

    .
    ├── s01                     # Set 1 - Basics
    │   ├── c01                 # Challenge 1 - Convert hex to base64
    │   |   ├── README.md       # README for challenge 1
    │   |   ├── c01.py          # Solution for challenge 1
    |   |   └── test_c01.py     # Test for challenge 1 solution
    |   ├── ...
    |   ├── c04                 # Challenge 4 - Detect single-character XOR
    │   |   ├── ...
    │   |   ├── helper_c04.py   # Previous (refactored) code used for current solution
    │   |   └── ...
    |   └── ...
    ├── s02                     # Set 2 - Block crypto
    |   └── ...
    ├── ...
    ├── .gitignore
    ├── LICENSE
    ├── README.md
    ├── pyproject.toml
    └── requirements.txt

### Sets

Each set of challenges has it's corresponding folder with the according number, e.g. the challenges from *Set 1 - Basics* reside in folder **s01**.

### Challenges

Every challenge has it's corresponding folder with the according number, e.g. the *Challenge 1 - Convert hex to base64* has it's own folder **c01**.

#### Solution

The solution for the particular challenge must be included within the corresponding function that returns the result (solution), e.g. solution for *Challenge 1 - Convert hex to base64* must return the result (solution) from the **c01()** function. Any "helper" code can be written outside of the corresponding function as long as it returns the result for futher testing. The solution is available in a python file named after the folder name, e.g. solution for *Challenge 1 - Convert hex to base64* is in **c01.py**.

```python
#
#   01 - Convert hex to base64
#

def helper_function(input):
    ...

def c01(input):
    ...

    return solution
```

#### Test

Test for the solution has a *"test\_"* prefix added to it, e.g. test for solution *c01.py* is in **test\_c01.py**. The test is always calling the corresponding method for the solution, e.g. *test\_c01()* must call **c01()**:

```python
#
#   01 - Convert hex to base64
#

from c01 import c01

def test_c01() -> None:
    input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    result = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    
    assert c01(input) == result
```

(The result is visible on the cryptopals site, so no spoiler here.)

#### Helper

Helper contains (refactored) code from previous solutions that is used for the current challenge. It has a *"helper\_"* prefix added to it, e.g. helper for solution *c04.py* is in **helper\_c04.py**.

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
$ source venv/bin/activate
```

#### Deactivation

```shell
# Deactivate The Virtual Environment After Being Done Running This Project
(venv) $ deactivate
```

### Dependencies

The dependencies must be installed for everything to work properly by running the following command:

```python
# Install The Dependencies For The Virtual Environment
(venv) $ python -m pip install -r requirements.txt
```

### Tests

#### Running The Tests

To run the tests for the solutions, run the pytest command:

```bash
# Run pytest With The Verbosity Flag
(venv) $ pytest -v

test_c01.py::test_c01 PASSED                                                                                        [100%]
```

#### Timeout

The timeout for every test is set to **60 seconds** by default, however it may be increased in the future if the solutions take longer to give the final result for the tests. This timeout can be configured in the *pyproject.toml* file as follows:

```
[tool.pytest.ini_options]
timeout = 60
```

## Table Of Contents

<ul>
    <li><b>Set 1: Basics</b></li>
    <ol type="1">
        <li>Convert hex to base64 :heavy_check_mark:</li>
        <li>Fixed XOR :heavy_check_mark:</li>
        <li>Single-byte XOR cipher :heavy_check_mark:</li>
        <li>Detect single-character XOR :heavy_check_mark:</li>
        <li>Implement repeating-key XOR :heavy_check_mark:</li>
        <li>Break repeating-key XOR :heavy_check_mark:</li>
        <li>AES in ECB mode :heavy_check_mark:</li>
        <li>Detect AES in ECB mode :heavy_check_mark:</li>
    </ol>
    <li><b>Set 2: Block crypto</b></li>
    <ol type="1" start="9">
        <li>Implement PKCS#7 padding :heavy_check_mark:</li>
        <li>Implement CBC mode :heavy_check_mark:</li>
        <li>An ECB/CBC detection oracle :heavy_check_mark:</li>
        <li>Byte-at-a-time ECB decryption (Simple) :heavy_check_mark:</li>
        <li>ECB cut-and-paste :heavy_check_mark:</li>
        <li>Byte-at-a-time ECB decryption (Harder) :heavy_check_mark:</li>
        <li>PKCS#7 padding validation :heavy_check_mark:</li>
        <li>CBC bitflipping attacks :x:</li>
    </ol>
    <li><b>Set 3: Block & stream crypto</b></li>
    <ol type="1" start="17">
        <li>The CBC padding oracle :x:</li>
        <li>Implement CTR, the stream cipher mode :x:</li>
        <li>Break fixed-nonce CTR mode using substitutions :x:</li>
        <li>Break fixed-nonce CTR statistically :x:</li>
        <li>Implement the MT19937 Mersenne Twister RNG :x:</li>
        <li>Crack an MT19937 seed :x:</li>
        <li>Clone an MT19937 RNG from its output :x:</li>
        <li>Create the MT19937 stream cipher and break it :x:</li>
    </ol>
    <li><b>Set 4: Stream crypto and randomness</b></li>
    <ol type="1" start="25">
        <li>Break "random access read/write" AES CTR :x:</li>
        <li>CTR bitflipping :x:</li>
        <li>Recover the key from CBC with IV=Key :x:</li>
        <li>Implement a SHA-1 keyed MAC :x:</li>
        <li>Break a SHA-1 keyed MAC using length extension :x:</li>
        <li>Break an MD4 keyed MAC using length extension :x:</li>
        <li>Implement and break HMAC-SHA1 with an artificial timing leak :x:</li>
        <li>Break HMAC-SHA1 with a slightly less artificial timing leak :x:</li>
    </ol>
    <li><b>Set 5: Diffie-Hellman and friends</b></li>
    <ol type="1" start="33">
        <li>Implement Diffie-Hellman :x:</li>
        <li>Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection :x:</li>
        <li>Implement DH with negotiated groups, and break with malicious "g" parameters :x:</li>
        <li>Implement Secure Remote Password (SRP) :x:</li>
        <li>Break SRP with a zero key :x:</li>
        <li>Offline dictionary attack on simplified SRP :x:</li>
        <li>Implement RSA :x:</li>
        <li>Implement an E=3 RSA Broadcast attack :x:</li>
    </ol>
    <li><b>Set 6: RSA and DSA</b></li>
    <ol type="1" start="41">
        <li>Implement unpadded message recovery oracle :x:</li>
        <li>Bleichenbacher's e=3 RSA Attack :x:</li>
        <li>DSA key recovery from nonce :x:</li>
        <li>DSA nonce recovery from repeated nonce :x:</li>
        <li>DSA parameter tampering :x:</li>
        <li>RSA parity oracle :x:</li>
        <li>Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case) :x:</li>
        <li>Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case) :x:</li>
    </ol>
    <li><b>Set 7: Hashes</b></li>
    <ol type="1" start="49">
        <li>CBC-MAC Message Forgery :x:</li>
        <li>Hashing with CBC-MAC :x:</li>
        <li>Compression Ratio Side-Channel Attacks :x:</li>
        <li>Iterated Hash Function Multicollisions :x:</li>
        <li>Kelsey and Schneier's Expandable Messages :x:</li>
        <li>Kelsey and Kohno's Nostradamus Attack :x:</li>
        <li>MD4 Collisions :x:</li>
        <li>RC4 Single-Byte Biases :x:</li>
    </ol>
    <li><b>Set 8: Abstract Algebra</b></li>
    <ol type="1" start="57">
        <li>Diffie-Hellman Revisited: Small Subgroup Confinement :x:</li>
        <li>Pollard's Method for Catching Kangaroos :x:</li>
        <li>Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks :x:</li>
        <li>Single-Coordinate Ladders and Insecure Twists :x:</li>
        <li>Duplicate-Signature Key Selection in ECDSA (and RSA) :x:</li>
        <li>Key-Recovery Attacks on ECDSA with Biased Nonces :x:</li>
        <li>Key-Recovery Attacks on GCM with Repeated Nonces :x:</li>
        <li>Key-Recovery Attacks on GCM with a Truncated MAC :x:</li>
        <li>Truncated-MAC GCM Revisited: Improving the Key-Recovery Attack via Ciphertext Length Extension :x:</li>
        <li>Exploiting Implementation Errors in Diffie-Hellman :x:</li>
    </ol>
</ul>

## License
Everything in this repository is released under the terms of the MIT License. For more information, please see the file "LICENSE".
