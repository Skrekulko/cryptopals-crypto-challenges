from requests import get
from statistics import median
from collections import Counter
from itertools import count
from collections import defaultdict
from cryptopals.XOR import XOR
from cryptopals.utils import Blocks
from cryptopals.Oracle import Oracle, HashOracle
from cryptopals.converter import Converter
from cryptopals.PKCS import PKCS7
from cryptopals.Generator import Generator, MT19937, StaticMT19937
from cryptopals.hash import SHA1, MD4


class Frequency:
    # Frequency Of English Letters
    occurrence_english = {
        'a': 8.2389258, 'b': 1.5051398,
        'c': 2.8065007, 'd': 4.2904556,
        'e': 12.813865, 'f': 2.2476217,
        'g': 2.0327458, 'h': 6.1476691,
        'i': 6.1476691, 'j': 0.1543474,
        'k': 0.7787989, 'l': 4.0604477,
        'm': 2.4271893, 'n': 6.8084376,
        'o': 7.5731132, 'p': 1.9459884,
        'q': 0.0958366, 'r': 6.0397268,
        's': 6.3827211, 't': 9.1357551,
        'u': 2.7822893, 'v': 0.9866131,
        'w': 2.3807842, 'x': 0.1513210,
        'y': 1.9913847, 'z': 0.0746517
    }

    # List Of English Letter Frequencies
    dist_english = list(occurrence_english.values())

    @staticmethod
    def compute_fitting_quotient(data: bytes) -> float:
        counter = Counter(data)

        dist_text = [
            (counter.get(ord(ch), 0) * 100) / len(data)
            for ch in Frequency.occurrence_english
        ]

        return sum([abs(a - b) for a, b in zip(Frequency.dist_english, dist_text)]) / len(dist_text)


class Decipher:
    @staticmethod
    def single_byte_xor(encrypted_bytes: bytes) -> tuple[bytes, int, float]:
        original_text, encryption_key, min_fq = None, None, None

        for k in range(256):
            _input = XOR.single_byte(encrypted_bytes, k)
            _freq = Frequency.compute_fitting_quotient(_input)

            if min_fq is None or _freq < min_fq:
                encryption_key, original_text, min_fq = k, _input, _freq

        return original_text, encryption_key, min_fq

    @staticmethod
    def repeating_xor(data: bytes) -> tuple[bytes, bytes]:
        # Get The (Possible) Key Size
        key_len = Hamming.compute_key_length(data)

        # Split The Input Into Chunks
        chunks = list((data[i::key_len]) for i in range(key_len))

        # Get The Secret Key
        key = b"".join(Decipher.single_byte_xor(chunk)[1].to_bytes(1, "big") for chunk in chunks)

        # Get The Decrypted Data By XORing The Encrypted Data With The Secret Key
        xored = XOR.repeating(data, key)

        return xored, key

    @staticmethod
    def aes_ecb_postfix(oracle: Oracle) -> bytes:
        # Detect The Block Size
        block_size = Detector.block_size(oracle)

        # Detect Prefix Size
        prefix_size = Detector.prefix_size(oracle, block_size)

        # Calculate Postfix Size
        postfix_size = Detector.postfix_size(oracle, block_size, prefix_size)

        # Extract The Postfix
        decrypted_postfix = b""
        for _ in range(postfix_size):
            # Decrypted Postfix Size
            decrypted_postfix_size = len(decrypted_postfix)

            # Crafted Padding
            crafted_padding_size = (- decrypted_postfix_size - 1 - prefix_size) % block_size
            crafted_padding = b"A" * crafted_padding_size

            # Get The Target Block
            target_block_number = (decrypted_postfix_size + prefix_size) // block_size
            target_slice = slice(target_block_number * block_size, (target_block_number + 1) * block_size)
            target_block = oracle.encrypt(crafted_padding)[target_slice]

            # Brute-Force All The Possible Bytes
            for byte in range(256):
                crafted_input = crafted_padding + decrypted_postfix + Converter.int_to_hex(byte)
                crafted_block = oracle.encrypt(crafted_input)[target_slice]

                # Found Identical Blocks
                if crafted_block == target_block:
                    decrypted_postfix += Converter.int_to_hex(byte)
                    break

        return PKCS7.strip(decrypted_postfix, block_size)

    @staticmethod
    def aes_ecb_hijack(oracle: Oracle, message: bytes, postfix_bytes_to_isolate: int) -> bytes:
        # Detect The Block Size
        block_size = Detector.block_size(oracle)

        # Detect Prefix Size
        prefix_size = Detector.prefix_size(oracle, block_size)

        # Calculate Postfix Size
        postfix_size = Detector.postfix_size(oracle, block_size, prefix_size)

        """

        --------------------------------------------------------------------
        | prefix | pr-padding | message | m-padding  | po-padding | postfix |
        --------------------------------------------------------------------

        """

        # Construct Prefix And Message Padding
        prefix_padding_size = block_size - (prefix_size % block_size)
        prefix_padding = b"A" * prefix_padding_size

        message_padding_size = block_size - (len(message) % block_size)

        # Craft The Input
        crafted_message = PKCS7.padding(message, block_size)
        crafted_input = prefix_padding + crafted_message

        # Extract The Encrypted Blocks Containing The Message
        start_block = (prefix_size + prefix_padding_size) // block_size
        end_block =\
            (prefix_size + prefix_padding_size) // block_size\
            + (len(crafted_message) + message_padding_size) // block_size
        encrypted_message_blocks = Blocks.split_into_blocks(
            oracle.encrypt(crafted_input), block_size
        )[start_block:end_block]

        # Construct The Isolation Padding
        isolation_padding_size = block_size - ((prefix_size + postfix_size) % block_size) + postfix_bytes_to_isolate
        isolation_padding = b"A" * isolation_padding_size
        encrypted_isolation_blocks = Blocks.split_into_blocks(
            oracle.encrypt(isolation_padding),
            block_size
        )[:-(postfix_bytes_to_isolate // block_size + 1)]

        # Construct Hijacked Encrypted Data
        hijacked_data = encrypted_isolation_blocks + encrypted_message_blocks

        return b"".join(hijacked_data)

    @staticmethod
    def aes_cbc_injection(oracle: Oracle, plaintext: bytes) -> bytes:
        # Detect The Block Size
        block_size = Detector.block_size(oracle)

        # Detect The Prefix Size
        prefix_size = Detector.prefix_size_cbc(oracle, block_size)

        # Calculate Postfix Size
        postfix_size = Detector.postfix_size(oracle, block_size, prefix_size)

        # Unsupported Size
        if len(plaintext) > block_size:
            raise Exception("CBC injection supports only 1 block of plaintext!")

        # Pad The Plaintext From The Left
        if len(plaintext) % block_size != 0:
            plaintext = b"T" * (block_size - (len(plaintext) % block_size)) + plaintext

        # Construct Prefix And Postfix Paddings
        prefix_padding = b"P" * ((block_size - (prefix_size % block_size)) if prefix_size % block_size != 0 else 0)
        postfix_padding = b"P" * ((block_size - (postfix_size % block_size)) if postfix_size % block_size != 0 else 0)

        # Sacrificial Block
        sacrificial_block = b"S" * block_size

        # Dummy Block
        dummy_block = b"A" * block_size

        # Calculate Sacrificial And Plaintext Block Index
        sacrificial_block_index = (prefix_size + len(prefix_padding)) // block_size

        # Encrypt The Sacrificial Block + Dummy BLock
        encrypted_blocks = Blocks.split_into_blocks(
            oracle.encrypt(
                prefix_padding
                + sacrificial_block
                + dummy_block
                + postfix_padding
            ),
            block_size
        )

        # Extract The Ciphertext (Sacrificial) Block
        ciphertext_block = encrypted_blocks[sacrificial_block_index]

        # XOR The Ciphertext (Sacrificial) Block With Dummy Block
        before_xor_block = XOR.fixed(ciphertext_block, dummy_block)

        # XOR The Before XOR Block With (Known) Plaintext
        injected_block = XOR.fixed(before_xor_block, plaintext)

        # Inject The Block Into Encrypted Blocks
        injected_blocks = encrypted_blocks[:]
        injected_blocks[sacrificial_block_index] = injected_block

        return b"".join(injected_blocks)

    @staticmethod
    def cbc_random_padding_size(oracle: Oracle, ciphertext_block: bytes, iv: bytes, block_size: int) -> int:
        # Initial Padding Size
        padding_size = 0

        # Iterate Through All Possible Padding Sizes
        for i in range(block_size):
            # Predicted Padding Byte And Incorrect Padding Byte
            predicted_byte = (block_size - i).to_bytes(1, "big")
            incorrect_byte = ((block_size - i) + 1).to_bytes(1, "big")

            # Corresponding Byte Of The IV
            iv_byte = iv[i].to_bytes(1, "big")

            # Before XOR Byte Of Current Ciphertext Block
            before_xor_byte = XOR.fixed(iv_byte, predicted_byte)

            # Crafted Byte And Block
            crafted_byte = XOR.fixed(before_xor_byte, incorrect_byte)
            crafted_block = iv[:i] + crafted_byte + iv[(i + 1):]

            # Bit-Flipping
            flipped_cipher = crafted_block + ciphertext_block

            # Try Decrypting Using The Oracle
            try:
                oracle.decrypt(flipped_cipher, b"", iv)
                continue
            # Incorrect Padding
            except ValueError:
                padding_size = block_size - i
                break

        return padding_size

    @staticmethod
    def cbc_brute_force_random_padding(oracle: Oracle, ciphertext_block: bytes, iv: bytes) -> bytes:
        # Brute-Force Last Padding Byte
        for i in range(256):
            # Crafted IV
            crafted_byte = i.to_bytes(1, "big")
            crafted_iv = iv[:-1] + crafted_byte

            # Try To Decrypt And Check Last Padding For '\x02'
            try:
                oracle.decrypt(ciphertext_block, b"", crafted_iv)
            except ValueError:
                # Brute-Force Previous Byte
                for j in range(256):
                    # Crafted Previous Padding Byte
                    crafted_previous_byte = j.to_bytes(1, "big")

                    # Crafted IV
                    crafted_iv = iv[:-2] + crafted_previous_byte + crafted_byte

                    # Try To Decrypt And Check '\x02\x02' Padding
                    try:
                        oracle.decrypt(ciphertext_block, b"", crafted_iv)

                        # Corrupted Padding
                        before_xor_byte = XOR.fixed(iv[-2].to_bytes(1, "big"), b"\x02")
                        xored_byte = XOR.fixed(before_xor_byte, b"\x03")
                        crafted_iv = iv[:-2] + xored_byte + crafted_byte

                        # Try To Decrypt And Check Corrupted '\x03\x02' Padding
                        try:
                            oracle.decrypt(ciphertext_block, b"", crafted_iv)
                        except ValueError:
                            before_xor_bytes = XOR.fixed(b"\x02\x02", crafted_previous_byte + crafted_byte)
                            return before_xor_bytes
                    except ValueError:
                        continue
                continue
            # Previous Padding Byte May Be '\x02'
            else:
                # Corrupted Padding
                before_xor_byte = XOR.fixed(iv[-2].to_bytes(1, "big"), b"\x02")
                xored_byte = XOR.fixed(before_xor_byte, b"\x03")
                crafted_iv = iv[:-2] + xored_byte + crafted_byte

                # Try To Decrypt And Check Corrupted '\x03\x02' Padding
                try:
                    oracle.decrypt(ciphertext_block, b"", crafted_iv)
                except ValueError:
                    before_xor_bytes = XOR.fixed(b"\x02\x02", iv[-2].to_bytes(1, "big") + crafted_byte)
                    return before_xor_bytes

                continue

        raise Exception("Could not brute-force the padding!")

    @staticmethod
    def cbc_padding_oracle(oracle: Oracle):
        # Known Block Size
        block_size = 16

        # Get Random Cipher
        cipher = oracle.encrypt()
        encrypted, iv = cipher

        # Put Together The Ciphertext Blocks With IV
        ciphertext_blocks = [encrypted[i: i + block_size] for i in range(0, len(encrypted), block_size)]
        ciphertext_blocks = [iv] + ciphertext_blocks
        n_blocks = len(ciphertext_blocks)

        decrypted = b""

        # Traverse All The Ciphertext Blocks (Skipping Initial IV)
        for i in range(n_blocks - 1, 0, -1):
            # Current Ciphertext Block
            ciphertext_block = ciphertext_blocks[i]

            # Previous Ciphertext Block (IV)
            iv = ciphertext_blocks[i - 1]

            # Find Padding Size Of The Current Ciphertext Block
            padding_size = Decipher.cbc_random_padding_size(
                oracle,
                ciphertext_block,
                iv,
                block_size
            )

            # If Padding Size Is Not Zero
            if padding_size != 0:
                before_xor_bytes = XOR.fixed(
                    iv[-padding_size:],
                    padding_size.to_bytes(1, "big") * padding_size
                )
            else:
                # Brute-Force Initial Padding
                before_xor_bytes = Decipher.cbc_brute_force_random_padding(
                    oracle,
                    ciphertext_block,
                    iv
                )

                padding_size = len(before_xor_bytes)

            # Ciphertext Block Byte Position (Skipping Known Padding)
            for j in range(padding_size, block_size):
                # Crafted Padding (Without The nth Byte)
                padding = (j + 1).to_bytes(1, "big") * j

                # XORed Bytes
                xored_bytes = XOR.fixed(padding, before_xor_bytes)

                # Brute-Force Bit-Flipping For New Padding Byte
                for k in range(256):

                    # Crafted IV
                    crafted_iv = iv[:-(j + 1)] + k.to_bytes(1, "big") + xored_bytes

                    # Try To Decrypt And Check Padding
                    try:
                        oracle.decrypt(ciphertext_block, b"", crafted_iv)
                        before_xor_byte = XOR.fixed(k.to_bytes(1, "big"), (j + 1).to_bytes(1, "big"))
                        before_xor_bytes = before_xor_byte + before_xor_bytes
                        break
                    except ValueError:
                        continue

            decrypted = XOR.fixed(iv, before_xor_bytes) + decrypted

        return PKCS7.strip(decrypted, block_size)

    @staticmethod
    def aes_ctr_fixed_nonce(ciphertexts: list) -> list[bytes]:
        # Construct The Keystream
        keystream = b""
        for i in range(max(map(len, ciphertexts))):
            # Construct A Column Of nth Ciphertext Characters
            column = b""
            for ciphertext in ciphertexts:
                column += ciphertext[i].to_bytes(1, "little") if i < len(ciphertext) else b""

            # Break The Single Byte Using Frequency Analysis
            keystream += Decipher.single_byte_xor(column)[1].to_bytes(1, "little")

        # Decrypt The Ciphertexts
        plaintexts = []
        for ciphertext in ciphertexts:
            plaintexts.append(XOR.repeating(ciphertext, keystream))

        return plaintexts

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

    @staticmethod
    def mt19937_find_key(ciphertext: bytes, known_text: bytes, max_seed: int) -> int:
        found_key = None
        for i in range(1, max_seed):
            possible_plaintext = StaticMT19937.transform(ciphertext, i)
            if possible_plaintext.endswith(known_text):
                found_key = i
                break

        return found_key

    @staticmethod
    def aes_ctr_injection(oracle: Oracle, plaintext: bytes) -> bytes:
        # Prefix Size
        prefix_size = Detector.prefix_size_ctr(oracle)

        # Sacrificial Plaintext
        sacrificial_plaintext = b"A" * len(plaintext)

        # Sacrificial Ciphertext
        ciphertext = oracle.encrypt(sacrificial_plaintext)
        sacrificial_ciphertext = oracle.encrypt(sacrificial_plaintext)[prefix_size:prefix_size + len(plaintext)]

        # Calculate Keystream Bytes
        keystream = XOR.fixed(sacrificial_ciphertext, sacrificial_plaintext)

        # XOR The Keystream With The Plaintext
        xored = XOR.fixed(keystream, plaintext)

        # Modify Encrypted Data
        modified_ciphertext = ciphertext[:prefix_size] + xored + ciphertext[prefix_size + len(plaintext):]

        return modified_ciphertext

    @staticmethod
    def aes_cbc_iv_key(oracle: Oracle) -> bytes:
        # Detect Block Size
        block_size = Detector.block_size(oracle)

        # Detect Prefix Size
        prefix_size = Detector.prefix_size_cbc(oracle, block_size)

        # Crafted Blocks
        crafted_a = b"A" * block_size
        crafted_b = b"B" * block_size
        crafted_c = b"C" * block_size
        crafted_null = b"\x00" * block_size

        # (P_1, P_2, P_3) -> (C_1, C_2, C_3)
        ciphertext = oracle.encrypt(crafted_a + crafted_b + crafted_c)

        # (C_1, C_2, C_3) -> (C_1, 0, C_3)
        forced_ciphertext = (
                ciphertext[prefix_size:prefix_size + block_size]
                +
                crafted_null
                +
                ciphertext[prefix_size:prefix_size + block_size]
        )

        # Try To Decrypt
        try:
            oracle.decrypt(forced_ciphertext)
        except Exception as e:
            forced_plaintext = e.args[1]

            # (P'_1 XOR P'_3)
            return XOR.fixed(forced_plaintext[:block_size], forced_plaintext[-block_size:])

        raise Exception("Not able to get the key!")

    @staticmethod
    def sha1_length_extension_attack(
            oracle: HashOracle,
            original_mac: bytes,
            original_plaintext: bytes,
            new_plaintext: bytes
    ) -> [bytes, bytes]:
        # Try Different Key Sizes
        for key_size in range(129):
            # Forged Plaintext '(original-plaintext || glue-padding || new-plaintext)'
            forged_plaintext = SHA1.padding(
                Generator.random_bytes(key_size, key_size) + original_plaintext
            )[key_size:] + new_plaintext

            # Split Digest Into Registers
            h_registers = [original_mac[i * 4:i * 4 + 4] for i in range(len(original_mac) // 4)]

            # Forged MAC Including The New Plaintext With Size Of '(key-size + forged-plaintext-length)'
            forged_mac = SHA1.digest(new_plaintext, key_size + len(forged_plaintext), h_registers)

            if oracle.validate(forged_plaintext, forged_mac):
                return forged_plaintext, forged_mac

        # Unable To Guess The Key Size
        raise Exception("Unable to forge the new plaintext!")

    @staticmethod
    def md4_length_extension_attack(
            oracle: HashOracle,
            original_mac: bytes,
            original_plaintext: bytes,
            new_plaintext: bytes
    ) -> [bytes, bytes]:
        # Try Different Key Sizes
        for key_size in range(129):
            # Forged Plaintext '(key || original-plaintext || glue-padding || new-plaintext)'
            forged_plaintext = MD4.padding(
                Generator.random_bytes(key_size, key_size) + original_plaintext
            )[key_size:] + new_plaintext

            # Split Digest Into Registers
            h_registers = [original_mac[i * 4:i * 4 + 4] for i in range(len(original_mac) // 4)]

            # Forged MAC Including The New Plaintext With Size Of '(key-size + forged-plaintext-length)'
            forged_mac = MD4.digest(new_plaintext, key_size + len(forged_plaintext), h_registers)

            if oracle.validate(forged_plaintext, forged_mac):
                return forged_plaintext, forged_mac

        # Unable To Guess The Key Size
        raise Exception("Unable to forge the new plaintext!")

    @staticmethod
    def hmac_next_byte(known_bytes: bytes, text: bytes, hmac_size: int, rounds: int) -> bytes:
        # Array For Counting The Request Time For Every Possible Byte
        times = [[] for _ in range(256)]

        # Suffix Size
        suffix_size = hmac_size - len(known_bytes)

        # Performing Multiple Rounds For Better Statistical Evidence
        for _ in range(rounds):
            # Every Possible Character
            for i in range(256):
                suffix = i.to_bytes(1, "big") + (suffix_size - 1) * b"\x00"
                signature = known_bytes + suffix

                response = get(f"http://127.0.0.1:8082/test?file={text.hex()}&signature={signature.hex()}")

                # In Case The Correct Signature Was Found Already
                if response.status_code == 200:
                    return suffix

                times[i].append(response.elapsed.total_seconds())

        # Median Time
        median_times = [median(bytes_times) for bytes_times in times]

        # Get The Highest Median Time Byte
        best = max(range(256), key=lambda b: median_times[b])

        return best.to_bytes(1, "big")

    @staticmethod
    def hmac_timing_attack(text: bytes, hmac_size: int, rounds: int, max_hmac_bytes=None) -> bytes:
        # Known Bytes Of HMAC
        known_bytes = b""

        # Discover HMAC Bytes For HMAC Length
        while len(known_bytes) < hmac_size:
            # Testing Purposes
            if max_hmac_bytes is not None and len(known_bytes) >= max_hmac_bytes:
                return known_bytes
            known_bytes += Decipher.hmac_next_byte(known_bytes, text, hmac_size, rounds)

        # Check Final HMAC
        response = get(f"http://127.0.0.1:8082/test?file={text.hex()}&signature={known_bytes.hex()}")

        if response.status_code == 200:
            return known_bytes
        else:
            raise Exception("Unable to correctly guess the HMAC!")


class Hamming:
    @staticmethod
    def distance(byte_string1: bytes, byte_string2: bytes) -> int:
        # Initial Distance
        distance = 0

        # Compare Each Byte And Calculate The Total Distance
        for byte1, byte2 in zip(byte_string1, byte_string2):
            distance += bin(byte1 ^ byte2).count("1")

        return distance

    @staticmethod
    def score(input1: bytes, input2: bytes) -> float:
        # Calculate The Hamming Score (Total Distance Divided By The Minimal Length)
        return Hamming.distance(input1, input2) / (8 * min(len(input1), len(input2)))

    @staticmethod
    def compute_key_length(encrypted_data: bytes) -> int:
        min_score, key_len = None, None

        # For Quick Finding, The Top Is Capped At 40, But Correctly It Should Be Capped
        # At 'math.ceil(len(input) / 2)' (Might Also Result In Weird Or Wrong Answers)
        for klen in range(2, 40):
            # Process The Input Into Chunks Of 'klen' Size
            chunks = [
                encrypted_data[i: i + klen]
                for i in range(0, len(encrypted_data), klen)
            ]

            if len(chunks) >= 2 and len(chunks[-1]) <= len(chunks[-2]) / 2:
                chunks.pop()

            # Calculate The Different Scores
            _scores = []
            for i in range(0, len(chunks) - 1, 1):
                for j in range(i + 1, len(chunks), 1):
                    score = Hamming.score(chunks[i], chunks[j])
                    _scores.append(score)

            # Start The Next Loop If We've Got No Scores
            if len(_scores) == 0:
                continue

            # Total Score
            score = sum(_scores) / len(_scores)

            # Check If We've Got A Better Score
            if min_score is None or score < min_score:
                min_score, key_len = score, klen

        return key_len


class Detector:
    @staticmethod
    def single_character_xor(ciphers: list) -> tuple[bytes, int, float]:
        # Decipher Every Encrypted Line And Put Them Together
        deciphered = [Decipher.single_byte_xor(cipher) for cipher in ciphers]

        # Return The Deciphered Data And The Secret Key
        return min(deciphered, key=lambda t: t[2])

    @staticmethod
    def block_positions(data: bytes, block_size: int) -> defaultdict[bytes, [int]]:
        # Split The Data Into Blocks
        blocks = Blocks.split_into_blocks(data, block_size)

        # Get Positions Of The Blocks
        positions = defaultdict(list)
        for index, block in enumerate(blocks):
            positions[block].append(index)

        # Return The Blocks With Their Positions
        return positions

    @staticmethod
    def block_size(oracle: Oracle, return_new_block_padding=False) -> [int, int]:
        # Increment The Input Data Size
        for i in count(start=0):
            len1 = len(oracle.encrypt(b"A" * i))
            len2 = len(oracle.encrypt(b"A" * (i + 1)))

            # Difference Found
            if len2 > len1:
                # Return Required Padding Size For New Block
                if return_new_block_padding:
                    return len2 - len1, i
                else:
                    return len2 - len1

    @staticmethod
    def prefix_size(oracle: Oracle, block_size: int) -> int:
        # Find Repeating Blocks With Empty Input
        empty_positions = Detector.block_positions(oracle.encrypt(b""), block_size)

        for i in count(start=0):
            # Encrypted Data
            encrypted = oracle.encrypt(
                b"A" * block_size * 2
                + b"A" * i
            )

            # Check The Positions Of The Blocks
            positions = Detector.block_positions(encrypted, block_size)

            # Check If Any Repeating Blocks Appeared
            repeated_block, repeated_block_positions = None, None
            for block in positions:
                if block not in empty_positions and len(positions[block]) >= 2:
                    repeated_block = block
                    repeated_block_positions = positions[block]

            # Continue If They Did Not Appear
            if not repeated_block:
                continue

            # Change Bytes Until A Change In The Repeating Blocks Occur
            for j in count(start=1):
                # New Encrypted Data
                encrypted = oracle.encrypt(
                    b"B" * j
                    + b"A" * (block_size * 2 - j)
                    + b"A" * i
                )

                # Get The New Positions
                new_positions = Detector.block_positions(encrypted, block_size)

                # One Of The Blocks Got Corrupted
                if not len(new_positions[repeated_block]) >= 2:
                    return block_size * repeated_block_positions[0] - i

            raise Exception("Could not find the prefix size!")

    @staticmethod
    def postfix_size(oracle: Oracle, block_size: int, prefix_size) -> int:
        # Get Empty Input Encrypted Data
        encrypted_empty = oracle.encrypt(b"")

        # Get The Total Amount Of Blocks
        n_blocks_empty = Blocks.number_of_blocks(encrypted_empty, block_size)

        # Increase The Input Size Until New Block Appears
        for i in count(start=1):
            # Count The New Amount Of Blocks
            n_blocks = Blocks.number_of_blocks(
                oracle.encrypt(b"A" * i),
                block_size
            )

            # Difference Found
            if n_blocks != n_blocks_empty:
                return len(encrypted_empty) - (prefix_size + (i - 1))

    @staticmethod
    def prefix_size_cbc(oracle: Oracle, block_size: int) -> int:
        # Find Repeating Blocks With Two Identical Blocks As Input
        default_positions = Detector.block_positions(oracle.encrypt(b""), block_size)

        # Increase Until We Pad The Prefix
        for input_size in count(start=0):
            # Encrypted Plaintext
            encrypted = oracle.encrypt(
                b"A" * input_size
            )

            # Get The Positions Of The Blocks
            positions = Detector.block_positions(encrypted, block_size)

            # No New Block Appears
            if len(positions) == len(default_positions):
                continue

            # Inject Two Identical Plaintext Blocks Including The Padding
            encrypted = oracle.encrypt(
                b"A" * block_size * 2
                + b"A" * input_size
            )

            # Get Block Positions For Comparison
            default_positions = Detector.block_positions(encrypted, block_size)

            # Change Bytes Until A Change In The Blocks Occur
            old_position = None
            for j in count(start=1):
                # New Encrypted Plaintext
                encrypted = oracle.encrypt(
                    b"A" * (block_size * 2 - j)
                    + b"A" * input_size
                    + b"B" * j
                )

                # Get The Positions Of The Blocks
                positions = Detector.block_positions(encrypted, block_size)

                # Check For Corrupted Blocks
                for index, (original_block, new_block) in enumerate(zip(default_positions, positions)):
                    # Corrupted Block Found
                    if original_block != new_block:
                        # No Old Position Yet
                        if not old_position:
                            old_position = index
                            continue

                        if index < old_position:
                            return (block_size * (index + 1) + (j - 1)) - (block_size * 2 + input_size)

            raise Exception("Could not find the prefix size!")

    @staticmethod
    def prefix_size_ctr(oracle: Oracle) -> int:
        # No Input (Empty) Ciphertext
        ciphertext_empty = oracle.encrypt(b"")

        # Ciphertext With At Least One Byte Difference
        ciphertext_diff = oracle.encrypt(b"A")

        # Compare The Bytes For Difference
        for index, (byte1, byte2) in enumerate(zip(ciphertext_empty, ciphertext_diff)):
            if byte1 != byte2:
                return index

        # No Difference Means That There's No Postfix
        return len(ciphertext_empty)


class Cloner:
    @staticmethod
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

    @staticmethod
    def mt19937_clone(tempered_state: [int], version="32"):
        if version == "32":
            w = 32
        else:
            w = 64

        # Untemper The Tempered State
        untempered_state = [Cloner.mt19937_untemper(y, w) for y in tempered_state]

        # Clone The PRNG
        cloned_generator = MT19937(state=untempered_state, version="32")

        return cloned_generator
