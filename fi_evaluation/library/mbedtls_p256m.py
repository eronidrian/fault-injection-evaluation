from typing import Iterable

import copy
from numpy import uint32, uint8

from fi_evaluation.curve import Curve, SECP256R1
from fi_evaluation.library import Library
from fi_evaluation.library.p256m_reimplementation import u256_sub, p256_n, u256_cmov, u256_set32, m256_sub_p, \
    m256_set32, point_double, point_add, point_to_affine, p256_p, m256_to_bytes, scalar_from_bytes, point_from_bytes

NUM_BITS = 256

class MbedtlsP256m(Library):

    curve: Curve
    name = "mbedtls_p256m"

    def __init__(self, curve: Curve):
        super().__init__(curve)


    def generate_computational_loop_abort_results(self, public_key: bytes, private_key: bytes) -> Iterable[
        tuple[bytes, int]]:

        s_odd = [uint32(0) for _ in range(8)]
        py_neg = [uint32(0) for _ in range(8)]
        py_use = [uint32(0) for _ in range(8)]
        rz = [uint32(0) for _ in range(8)]

        rx = [uint32(0) for _ in range(8)]
        ry = [uint32(0) for _ in range(8)]

        s = [uint32(0) for _ in range(8)]
        px = [uint32(0) for _ in range(8)]
        py = [uint32(0) for _ in range(8)]


        scalar_from_bytes(s, [uint8(i) for i in list(private_key)])
        point_from_bytes(px, py, [uint8(i) for i in list(public_key)])

        secret = [uint8(0) for _ in range(32)]

        u256_sub(s_odd, p256_n.m, s)
        negate = ~s[0] & 1
        u256_cmov(s_odd, s, uint32(1) - negate)

        u256_set32(py_use, uint32(0))
        m256_sub_p(py_neg, py_use, py)

        u256_cmov(rx, px, uint32(1))
        u256_cmov(ry, py, uint32(1))
        m256_set32(rz, uint32(1), p256_p)
        u256_cmov(ry, py_neg, negate)

        for i in range(NUM_BITS - 1, 0, -1):
            bit = (s_odd[i // 32] >> i % 32) & 1

            u256_cmov(py_use, py, bit ^ negate)
            u256_cmov(py_use, py_neg, (1 - bit) ^ negate)

            point_double(rx, ry, rz)
            point_add(rx, ry, rz, px, py_use)

            entropy = 1 + NUM_BITS - 1 - i

            if i > 1:
                rx_copy = copy.deepcopy(rx)
                ry_copy = copy.deepcopy(ry)
                rz_copy = copy.deepcopy(rz)
                point_to_affine(rx_copy, ry_copy, rz_copy)
                m256_to_bytes(secret, rx_copy, p256_p)
                yield bytes(secret), entropy + 1


