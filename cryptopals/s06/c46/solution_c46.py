#
#   46 - RSA parity oracle
#

from cryptopals.asymmetric import RSA
from math import ceil, log
from decimal import Decimal, getcontext


class Oracle(RSA):
    def __init__(self, bits=2048, e=65537) -> None:
        # Initialize RSA
        super().__init__(bits=bits, e=e)

    def is_parity_odd(self, message: int) -> bool:
        if self.decrypt(message=message) % 2:
            return True

        return False


def rsa_parity_attack(oracle: Oracle, ciphertext: int) -> int:
    # Compute The Ciphertext Of 2, Which Is Used As The Ciphertext Multiplier
    multiplier = pow(2, oracle.parameters.e, oracle.parameters.n)

    # Initialize The Lower And The Upper Bound, And Use Decimal To Allow Better Precision
    lower_bound = Decimal(0)
    upper_bound = Decimal(oracle.parameters.n)

    # Number Of Iterations Needed
    k = int(ceil(log(oracle.parameters.n, 2)))

    # Precision Floating Point Number
    getcontext().prec = k

    # Binary Search
    for _ in range(k):
        ciphertext = (ciphertext * multiplier) % oracle.parameters.n

        if oracle.is_parity_odd(ciphertext):
            lower_bound = (lower_bound + upper_bound) / 2
        else:
            upper_bound = (lower_bound + upper_bound) / 2

    # Return The Binary Version Of The Upper bound
    return int(upper_bound)
