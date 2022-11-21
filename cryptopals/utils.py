from math import ceil
import codecs


def load_lines(file_name: str) -> list[bytes]:
    with open(file_name) as file:
        return [bytes.fromhex(line.rstrip()) for line in file.readlines()]


def load_data(file_name: str) -> bytes:
    with open(file_name) as file:
        data = file.read()
        data = codecs.decode(bytes(data.encode("ascii")), "base64")
        return data


class Blocks:
    @staticmethod
    def number_of_blocks(data: bytes, block_size: int, keep_non_multiple=False) -> int:
        if keep_non_multiple:
            return int(ceil(len(data) / block_size))
        else:
            return int(len(data) // block_size)

    @staticmethod
    def split_into_blocks(data: bytes, block_size: int, n_blocks=None, keep_non_multiple=False) -> [bytes]:
        if not n_blocks:
            # Calculate The Total Amount Of Blocks
            n_blocks = Blocks.number_of_blocks(data, block_size, keep_non_multiple)

        return [(data[i * block_size: i * block_size + block_size]) for i in range(n_blocks)]


class Math:
    @staticmethod
    # Modular Exponentiation 'a^b mod m'
    def mod_pow(b: int, e: int, m: int) -> int:
        x = 1

        while e > 0:
            b, e, x = (
                b * b % m,
                e // 2,
                b * x % m if e % 2 else x
            )

        return x

    @staticmethod
    # Greatest Common Divider
    def gcd(a: int, b: int) -> int:
        return Math.gcd(b, a % b) if b else abs(a)

    @staticmethod
    # Least Common Multiple
    def lcm(a: int, b: int) -> int:
        return abs(a * b) // Math.gcd(a, b) if a and b else 0

    @staticmethod
    # Modular Inverse
    def mod_inv(a: int, n: int) -> int:
        t, r = 0, n
        new_t, new_r = 1, a

        while new_r != 0:
            quotient = r // new_r
            t, new_t = new_t, t - quotient * new_t
            r, new_r = new_r, r - quotient * new_r

        if r > 1:
            raise Exception("'a' does not have a modular inverse!")

        if t < 0:
            t = t + n

        return t
