#
#   22 - Crack an MT19937 seed
#

from cryptopals.s03.c22.solution_c22 import Decipher
from time import time
from random import randint
from cryptopals.Generator import MT19937


def test_c22() -> None:
    # Get Current Time
    current_time = int(time())
    
    # Calculate Delta Time And Create A New Time Seed
    START_TIME, END_TIME = 40, 10000
    delta1 = randint(START_TIME, END_TIME)
    time_seed = current_time + delta1
    delta2 = randint(START_TIME, END_TIME)
    
    # Create A New Generator
    generator = MT19937(time_seed)
    
    # Generate A Random Number
    target_number = generator.extract_number()
    
    # Calculate Time Of Output
    output_time = current_time + delta1 + delta2
    
    assert Decipher.mt19937_find_seed(target_number, START_TIME, END_TIME, output_time) == time_seed
