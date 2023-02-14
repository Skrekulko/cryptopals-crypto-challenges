#
#   42 - Bleichenbacher's e=3 RSA Attack
#

from cryptopals.s06.c42.solution_c42 import Oracle, bleichenbacher_signature


def test_c42() -> None:
    # RSA Oracle
    oracle = Oracle(e=3)

    # Message
    message = b"\x00\x00\x2e\x36"

    # Forged Signature
    forged_signature = bleichenbacher_signature(
        n_size=oracle.parameters.size_in_bits(),
        e=oracle.parameters.e,
        message=message
    )

    assert oracle.verify(signature=forged_signature, message=message)
