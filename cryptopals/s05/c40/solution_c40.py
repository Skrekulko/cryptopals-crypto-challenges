#
#   40 - Implement an E=3 RSA Broadcast attack
#

from functools import reduce
from cryptopals.utils import Math, Converter


class MyMath(Math):
    @staticmethod
    # Integer Root 'Nth' Of 'X'
    def root(a: int, b: int) -> int:
        # Root Is Less Than 2 (Root Is 1)
        if b < 2:
            return b

        a1 = a - 1
        c = 1
        d = (a1 * c + b // (c ** a1)) // a
        e = (a1 * d + b // (d ** a1)) // a

        while c not in (d, e):
            c, d, e = d, e, (a1 * e + b // (e ** a1)) // a

        return min(d, e)


# RSA Broadcast Attack (Coppersmith's Attack)
def rsa_broadcast_attack(rsa_c: [bytes], rsa_n: [int], e: int) -> bytes:
    rsa_m = []
    for i, n in enumerate(rsa_n):
        rsa_m.append(reduce(lambda x, y: x * y, rsa_n[:i] + rsa_n[i + 1:]))
    
    t = [int.from_bytes(c, "big") * m * MyMath.mod_inv(m, n) for (c, m, n) in zip(rsa_c, rsa_m, rsa_n)]
    
    c = sum(t) % reduce(lambda x, y: x * y, rsa_n)

    return Converter.int_to_hex(MyMath.root(e, c))
