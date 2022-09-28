#
#   22 - Crack an MT19937 seed
#

from helper_c22 import MT19937

def crack_mt19937_seed(target_number: int, start_time: int, end_time: int, output_time: int) -> int:
    # Start Brute-Forcing From Start To End Time
    for i in range(start_time, end_time):
        # Calculate Possible Time
        possible_seed = output_time - i
        
        # Create A New Generator
        generator = MT19937(possible_seed, version = "32")
        
        # Compare The First Generated Number With The Target Number
        if generator.extract_number() == target_number:
            return possible_seed
    # Not Found
    else:
        raise Exception("Unable to regenerate the random number!")


def c22(target_number: int, start_time: int, end_time: int, output_time: int) -> int:
    return crack_mt19937_seed(target_number, start_time, end_time, output_time)