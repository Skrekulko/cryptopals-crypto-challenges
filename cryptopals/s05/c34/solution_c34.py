#
#   34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
#

from cryptopals.asymmetric import DiffieHellman
from cryptopals.utils import Generator, Converter
from cryptopals.hash import SHA1
from cryptopals.symmetric import AES128CBC


class Decipher:
    @staticmethod
    def dh_parameter_injection(
            alice: DiffieHellman, alice_plaintext: bytes,
            bob: DiffieHellman, bob_plaintext: bytes
    ) -> tuple[bytes, bytes]:
        # Step 1: Alice Sends Her Public Key 'A' To Bob (Intercepted By Eva)

        # Step 2: Eva Sends 'p' To Bob
        bob.set_ssk(pk=alice.p)

        # Step 3: Bob Sends His Public Key 'B' To Alice (Intercepted By Eva)

        # Step 4: Eva Sends 'p' To Alice
        alice.set_ssk(pk=bob.p)

        # Step 5: Alice Sends Her Ciphertext To Bob (Intercepted By Eva)
        key = SHA1.digest(m=Converter.int_to_hex(alice.ssk))[:AES128CBC.BLOCK_SIZE]
        iv = Generator.key_128b()
        ciphertext_a = AES128CBC.encrypt(alice_plaintext, key, iv) + iv

        # Step 6: Eva Sends The Ciphertext To Bob

        # Step 7: Bob Sends His Ciphertext To Alice (Intercepted By Eva)
        key = SHA1.digest(m=Converter.int_to_hex(bob.ssk))[:AES128CBC.BLOCK_SIZE]
        iv = Generator.key_128b()
        ciphertext_b = AES128CBC.encrypt(bob_plaintext, key, iv) + iv

        # Step 8: Eva Sends The Ciphertext To Alice

        # Get Secret Key For AES
        mitm_key = SHA1.digest(b"\x00")[:AES128CBC.BLOCK_SIZE]

        # Get Alice's And Bob's IVs
        mitm_alice_iv = ciphertext_a[-AES128CBC.BLOCK_SIZE:]
        mitm_bob_iv = ciphertext_b[-AES128CBC.BLOCK_SIZE:]

        # Decrypt Alice's And Bob's Plaintexts
        alice_plaintext = AES128CBC.decrypt(ciphertext_a[:-AES128CBC.BLOCK_SIZE], mitm_key, mitm_alice_iv)
        bob_plaintext = AES128CBC.decrypt(ciphertext_b[:-AES128CBC.BLOCK_SIZE], mitm_key, mitm_bob_iv)

        return alice_plaintext, bob_plaintext
