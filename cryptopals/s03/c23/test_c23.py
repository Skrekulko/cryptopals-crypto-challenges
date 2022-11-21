#
#   23 - Clone an MT19937 RNG from its output
#

from cryptopals.s03.c23.solution_c23 import Cloner
from cryptopals.generator import MT19937


def test_c23() -> None:
    # Default Seed
    DEFAULT_SEED = 5489
    
    # Size Of State Vector
    VECTOR_SIZE = 624

    # Create A New Generator
    generator = MT19937(DEFAULT_SEED)
    
    # Advance The Generator
    for _ in range(DEFAULT_SEED):
        generator.extract_number() 
    
    # Generate 624 Random Numbers
    tempered_state = [generator.extract_number() for _ in range(VECTOR_SIZE)]
    
    # Cloned PRNG
    cloned_generator = Cloner.mt19937_clone(tempered_state)
    
    # Test For 'VECTOR_SIZE' Numbers
    for _ in range(VECTOR_SIZE):    
        assert cloned_generator.extract_number() == generator.extract_number()
