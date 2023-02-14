#
#   47 - Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)
#

from cryptopals.s06.c48.solution_c48 import Oracle, bleichenbacher_chosen_plaintext


def test_c48() -> None:
    # RSA Oracle
    oracle = Oracle(bits=256)

    # Message
    message = b"RSA256"

    # Ciphertext
    ciphertext = oracle.encrypt(message=message)

    # Recovered Message
    recovered_message = bleichenbacher_chosen_plaintext(oracle=oracle, ciphertext=ciphertext)

    assert message == oracle.decode(message=recovered_message)
