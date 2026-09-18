from typing import Iterable

from fi_evaluation.curve import Curve
from fi_evaluation.library import Library


class MbedtlsP256m(Library):

    curve: Curve
    name = "mbedtls_p256m"

    def __init__(self, curve: Curve):
        super().__init__(curve)


    def generate_computational_loop_abort_results(self, public_key: bytes, private_key: bytes) -> Iterable[
        tuple[bytes, int]]:

        with open("fi_evaluation/library/mbedtls_loop_abort", "r") as f:
            content = f.read().splitlines()

        for i, line in enumerate(content):
            yield bytes.fromhex(line), i
