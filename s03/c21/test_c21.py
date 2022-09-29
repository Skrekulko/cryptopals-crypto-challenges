#
#   21 - Implement the MT19937 Mersenne Twister RNG
#

from c21 import c21, MT19937

def test_c21() -> None:
    # Default Seed Value Used In MT19937
    default_seed = 5489
    
    # Create And Seed The PRNG
    mt = MT19937(version = "32")
    mt.seed(default_seed)
    
    # Generate The Test Set
    test_set = [mt.extract_number() for i in range(default_seed)]
    
    assert c21(default_seed) == test_set
