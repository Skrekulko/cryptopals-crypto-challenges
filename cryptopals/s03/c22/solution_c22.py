#
#   22 - Crack an MT19937 seed
#

from cryptopals.generator import MT19937


class Decipher:
    @staticmethod
    def mt19937_find_seed(target_number: int, start_time: int, end_time: int, output_time: int) -> int:
        # Start Brute-Forcing From Start To End Time
        for i in range(start_time, end_time):
            # Calculate Possible Time
            possible_seed = output_time - i

            # Create A New Generator
            generator = MT19937(possible_seed)

            # Compare The First Generated Number With The Target Number
            if generator.extract_number() == target_number:
                return possible_seed
        # Not Found
        else:
            raise Exception("Unable to regenerate the random number!")
