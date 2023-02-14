#
#   35 - Implement DH with negotiated groups, and break with malicious "g" parameters
#

from cryptopals.asymmetric import DiffieHellman
from cryptopals.hash import SHA1
from cryptopals.symmetric import AES128CBC
from cryptopals.utils import Generator, Converter


class Decipher:
    @staticmethod
    def dh_malicious_g(g: int, alice: DiffieHellman, alice_plaintext: bytes, bob: DiffieHellman) -> [bytes]:
        # Step 1: Alice Sends 'p' And 'g' To Bob (Intercepted By Eva)
        p = alice.p
        bob.g = g
        bob.pk = DiffieHellman.calculate_pk(sk=bob.sk, g=bob.g, p=bob.p)

        # Step 2: Bob Receives Forced 'g' And Sends ACK To Alice

        # Step 3: Alice Sends Her Public Key 'A' To Bob (Intercepted By Eva)
        A = alice.pk
        bob.set_ssk(A)

        # Step 4: Bob Sends His Public Key
        B = bob.pk
        alice.set_ssk(B)

        # Step 5: Alice Sends Her Ciphertext To Bob (Intercepted And Relayed By Eva)
        ssk = Converter.int_to_hex(alice.ssk)
        key = SHA1.digest(m=ssk)[:AES128CBC.BLOCK_SIZE]
        iv = Generator.key_128b()
        ciphertext = AES128CBC.encrypt(alice_plaintext, key, iv) + iv

        # Step 6: Bob Receives The Ciphertext From Alice

        # Get The IV For AES
        mitm_iv = ciphertext[-AES128CBC.BLOCK_SIZE:]

        # Get The Secret Key For AES
        # g == 1
        if g == 1:
            mitm_key = SHA1.digest(b"\x01")[:AES128CBC.BLOCK_SIZE]
            mitm_plaintext = AES128CBC.decrypt(ciphertext[:-AES128CBC.BLOCK_SIZE], mitm_key, mitm_iv)
        # g == p
        elif g == alice.p:
            mitm_key = SHA1.digest(b"\x00")[:AES128CBC.BLOCK_SIZE]
            mitm_plaintext = AES128CBC.decrypt(ciphertext[:-AES128CBC.BLOCK_SIZE], mitm_key, mitm_iv)
        # g == (p - 1): (-1)^(ab) => (+1 % p) || (-1 % p)
        else:
            # Both Possible Plaintexts
            mitm_plaintext = []

            # Try For Each Secret Key
            for candidate in [1, p - 1]:
                mitm_key = SHA1.digest(Converter.int_to_hex(candidate))[:AES128CBC.BLOCK_SIZE]

                # Decrypt
                try:
                    mitm_plaintext.append(AES128CBC.decrypt(ciphertext[:-AES128CBC.BLOCK_SIZE], mitm_key, mitm_iv))
                except ValueError:
                    continue

        return mitm_plaintext
