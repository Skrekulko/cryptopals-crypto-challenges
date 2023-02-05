#
#   46 - RSA parity oracle
#

from cryptopals.asymmetric import RSA


class Oracle(RSA):
    def __init__(self, bits=2048, e=65537) -> None:
        # Initialize RSA
        super().__init__(bits=bits, e=e)

    def is_parity_odd(self, message: int) -> bool:
        if self.decrypt(message=message) % 2:
            return True

        return False