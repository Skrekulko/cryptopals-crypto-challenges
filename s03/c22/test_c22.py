#
#   22 - Crack an MT19937 seed
#

from c22 import c22
from helper_c22 import MT19937
from time import time
from random import randint

def test_c22() -> None:
    # Get Current Time
    current_time = int(time())
    
    # Calculate Delta Time And Create A New Time Seed
    START_TIME, END_TIME = 40, 10000
    delta1 = randint(START_TIME, END_TIME)
    time_seed = current_time + delta1
    delta2 = randint(START_TIME, END_TIME)
    
    # Create A New Generator
    generator = MT19937(time_seed, version = "32")
    
    # Generator A Random Number
    target_number = generator.extract_number()
    
    # Calculate Time Of Output
    output_time = current_time + delta1 + delta2
    
    assert c22(target_number, START_TIME, END_TIME, output_time) == time_seed
