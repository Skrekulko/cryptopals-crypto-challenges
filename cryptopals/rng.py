# noinspection PyTypeChecker
class MT19937:
    # Default Seed
    DEFAULT_SEED = 5489

    def __init__(self, seed=DEFAULT_SEED, state=None, version="32") -> None:
        # 32-Bit
        if version == "32":
            self.w, self.n, self.m, self.r = 32, 624, 397, 31
            self.a = 0x9908b0df
            self.u, self.d = 11, 0xffffffff
            self.s, self.b = 7, 0x9d2c5680
            self.t, self.c = 15, 0xefc60000
            self.L = 18
            self.f = 1812433253
        # 64-Bit
        else:
            self.w, self.n, self.m, self.r = 64, 312, 156, 31
            self.a = 0xb5026f5aa96619e9
            self.u, self.d = 29, 0x5555555555555555
            self.s, self.b = 17, 0x71d67fffeda60000
            self.t, self.c = 37, 0xfff7eee000000000
            self.L = 45
            self.f = 6364136223846793005

        # Create A Length 'n' Array To Store The State Of The Generator
        if state is None:
            self.MT = self.n * [None]
        else:
            self.MT = state
        self.index = self.n + 1
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = (~self.lower_mask) & ((1 << self.w) - 1)

        # Initialize The Generator From A Seed
        self.index = self.n
        if state is None:
            self.MT[0] = seed
            for i in range(1, self.n):
                self.MT[i] = (
                    self.f * (
                        self.MT[i - 1] ^ (self.MT[i - 1] >> (self.w - 2))) + i
                ) & ((1 << self.w) - 1)

    # Generate The Next 'n' Values From The Series 'x_i'
    def twist(self) -> None:
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) | (self.MT[(i + 1) % self.n] & self.lower_mask)
            xA = x >> 1

            # Lowest Bit Of 'x' Is 1
            if (x % 2) != 0:
                xA = xA ^ self.a

            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA

        self.index = 0

    # Extract A Tempered Value Based On 'MT[index]' Calling 'twist()' Every 'n' Numbers
    def extract_number(self) -> int:
        if self.index >= self.n:
            if self.index > self.n:
                raise Exception("Generator is not seeded!")

            self.twist()

        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.L)

        self.index += 1

        return y & ((1 << self.w) - 1)


class StaticMT19937:
    @staticmethod
    def keystream(key: int):
        if key.bit_length() > 16:
            raise Exception("Not a 16-bit key!")

        generator = MT19937(key)

        while True:
            random_number = generator.extract_number()
            yield from random_number.to_bytes(4, "big")

    @staticmethod
    def transform(plaintext: bytes, key: int):
        return bytes([x ^ y for (x, y) in zip(plaintext, StaticMT19937.keystream(key))])
