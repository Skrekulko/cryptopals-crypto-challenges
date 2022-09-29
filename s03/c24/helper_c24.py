#
#   11 - An ECB/CBC detection oracle
#

from random import randint
from os import urandom

class Generator:
    @staticmethod
    def generate_random_bytes(min = 1, max = 16) -> bytes:
        return urandom(randint(min, max))
        
    @staticmethod
    def generate_key_128b() -> bytes:
        return urandom(16)


#
#   21 - Implement the MT19937 Mersenne Twister RNG
#

# MT1937 Mersenne Twister RNG
class MT19937:
    # Default Seed
    DEFAULT_SEED = 5489
    
    def __init__(self, seed = DEFAULT_SEED, state = None, version = "32") -> None:
        # 32-Bit
        if version == "32":
            self.w, self.n, self.m, self.r = 32, 624, 397, 31
            self.a = 0x9908b0df
            self.u, self.d = 11, 0xffffffff
            self.s, self.b = 7, 0x9d2c5680
            self.t, self.c = 15, 0xefc60000
            self.l = 18
            self.f = 1812433253
        # 64-Bit
        else:
            self.w, self.n, self.m, self.r = 64, 312, 156, 31
            self.a = 0xb5026f5aa96619e9
            self.u, self.d = 29, 0x5555555555555555
            self.s, self.b = 17, 0x71d67fffeda60000
            self.t, self.c = 37, 0xfff7eee000000000
            self.l = 45
            self.f = 6364136223846793005
        
        # Create A Length 'n' Array To Store The State Of The Generator
        if state == None:
            self.MT = self.n * [None]
        else:
            self.MT = state
        self.index = self.n + 1
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = (~self.lower_mask) & ((1 << self.w) - 1)

        # Initialize The Generator From A Seed
        self.index = self.n
        if state == None:
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
        y = y ^ (y >> self.l)
        
        self.index += 1
        
        return y & ((1 << self.w) - 1)

#
#   23 - Clone an MT19937 RNG from its output
#

def mt19937_untemper(y: int, w: int) -> int:
    # PRNG Parameters
    u, d = 11, 0xffffffff
    s, b = 7, 0x9d2c5680
    t, c = 15, 0xefc60000
    l = 18
    
    # Untemper
    y ^= y >> l
    y ^= y << t & c
    for _ in range(s):
        y ^= y << s & b
    for _ in range(u + s - t):
        y ^= y >> u & d
    
    return y & ((1 << w) - 1)

def mt19937_clone(tempered_state: [int], version = "32"):
    if version == "32":
        w = 32
    else:
        w = 64

    # Untemper The Tempered State
    untempered_state = [mt19937_untemper(y, w) for y in tempered_state]
    
    # Clone The PRNG
    cloned_generator = MT19937(state = untempered_state, version = "32")
    
    return cloned_generator
    
