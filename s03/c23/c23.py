#
#   23 - Clone an MT19937 RNG from its output
#

from helper_c23 import MT19937

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

def c23(tempered_state: [int]) -> MT19937:
    return mt19937_clone(tempered_state)
