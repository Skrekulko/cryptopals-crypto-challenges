#
#   21 - Implement the MT19937 Mersenne Twister RNG
#

from cryptopals.s03.c21.solution_c21 import MT19937


def test_c21() -> None:
    # Default Seed Value Used In MT19937
    default_seed = 5489
    
    # Create And Seed The PRNG
    mt_A = MT19937(default_seed)
    mt_B = MT19937(default_seed)
    
    # Generate The Test Set
    test_set_A = [mt_A.extract_number() for _ in range(default_seed)]
    test_set_B = [mt_B.extract_number() for _ in range(default_seed)]

    assert test_set_A == test_set_B
