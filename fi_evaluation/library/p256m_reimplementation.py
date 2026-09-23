from numpy import uint32, uint64, uint8


class p256_p:
    m = [uint32(i) for i in [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                             0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF]]
    R2 = [uint32(i) for i in [0x00000003, 0x00000000, 0xffffffff, 0xfffffffb,
                              0xfffffffe, 0xffffffff, 0xfffffffd, 0x00000004]]
    ni = uint32(0x00000001)


class p256_n:
    m = [uint32(i) for i in [0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
                             0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF]]
    R2 = [uint32(i) for i in [0xbe79eea2, 0x83244c95, 0x49bd6fa6, 0x4699799c,
                              0x2b6bec59, 0x2845b239, 0xf3d95620, 0x66e12d94]]
    ni = uint32(0xee00bc4f)

p256_b = [uint32(i) for i in [  0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd,
    0xf7212ed6, 0xe5a220ab, 0x04874834, 0xdc30061d]]


def u256_sub(z: list[uint32], x: list[uint32], y: list[uint32]) -> uint32:
    carry = uint32(0)
    for i in range(8):
        diff = uint64(x[i]) - y[i] - carry
        z[i] = uint32(diff)
        carry = - uint32(diff >> 32)

    return carry


def u256_cmov(z: list[uint32], x: list[uint32], c: uint32) -> None:
    x_mask = uint32(-c)
    for i in range(8):
        z[i] = (z[i] & ~x_mask) | (x[i] & x_mask)


def u256_set32(z: list[uint32], x: uint32) -> None:
    z[0] = x
    for i in range(1, 8):
        z[i] = uint32(0)


def u256_add(z: list[uint32], x: list[uint32], y: list[uint32]) -> uint32:
    carry: uint32 = uint32(0)

    for i in range(8):
        _sum = uint64(carry) + x[i] + y[i]
        z[i] = uint32(_sum)
        carry = uint32(_sum >> 32)

    return carry


def m256_sub(z: list[uint32], x: list[uint32], y: list[uint32], mod: type[p256_p] | type[p256_n]) -> None:
    r = [uint32(0) for _ in range(8)]
    carry = u256_sub(z, x, y)
    u256_add(r, z, mod.m)

    u256_cmov(z, r, carry)


def m256_sub_p(z: list[uint32], x: list[uint32], y: list[uint32]) -> None:
    m256_sub(z, x, y, p256_p)


def u32_muladd64(x: uint32, y: uint32, z: uint32, t: uint32) -> uint64:
    return uint64(x) * y + z + t


def u288_muladd_step(i: int, x: uint32, y: list[uint32], z: list[uint32], carry: uint32) -> uint32:
    prod = u32_muladd64(x, y[i], z[i], carry)
    z[i] = uint32(prod)
    carry = uint32(prod >> 32)

    return carry


def u288_muladd(z: list[uint32], x: uint32, y: list[uint32]) -> uint32:
    carry = uint32(0)

    for i in range(8):
        carry = u288_muladd_step(i, x, y, z, carry)

    _sum = uint64(z[8]) + carry
    z[8] = uint32(_sum)
    carry = uint32(_sum >> 32)

    return carry


def u288_rshift32(z: list[uint32], c: uint32) -> None:
    for i in range(8):
        z[i] = z[i + 1]

    z[8] = c


def m256_mul(z: list[uint32], x: list[uint32], y: list[uint32], mod: type[p256_p] | type[p256_n]) -> None:
    m_prime = mod.ni
    a = [uint32(0) for _ in range(9)]

    for i in range(9):
        a[i] = uint32(0)

    for i in range(8):
        u = (a[0] + x[i] * y[0]) * m_prime

        c = u288_muladd(a, x[i], y)
        c += u288_muladd(a, u, mod.m)
        u288_rshift32(a, c)

    carry_add = a[8]
    carry_sub = u256_sub(z, a, mod.m)
    use_sub = carry_add | (1 - carry_sub)
    u256_cmov(z, a, 1 - use_sub)


def m256_prep(z: list[uint32], mod: type[p256_p] | type[p256_n]) -> None:
    m256_mul(z, z, mod.R2, mod)


def m256_set32(z: list[uint32], x: uint32, mod: type[p256_n] | type[p256_p]) -> None:
    u256_set32(z, x)
    m256_prep(z, mod)


def m256_mul_p(z: list[uint32], x: list[uint32], y: list[uint32]) -> None:
    m256_mul(z, x, y, p256_p)


def m256_add(z: list[uint32], x: list[uint32], y: list[uint32], mod: type[p256_p] | type[p256_n]) -> None:
    r = [uint32(0) for _ in range(8)]
    carry_add = u256_add(z, x, y)
    carry_sub = u256_sub(r, z, mod.m)

    use_sub = carry_add | (1 - carry_sub)
    u256_cmov(z, r, use_sub)


def m256_add_p(z: list[uint32], x: list[uint32], y: list[uint32]) -> None:
    m256_add(z, x, y, p256_p)


def point_double(x: list[uint32], y: list[uint32], z: list[uint32]) -> None:
    m = [uint32(0) for _ in range(8)]
    s = [uint32(0) for _ in range(8)]
    u = [uint32(0) for _ in range(8)]

    m256_mul_p(s, z, z)
    m256_add_p(m, x, s)
    m256_sub_p(u, x, s)
    m256_mul_p(s, m, u)
    m256_add_p(m, s, s)
    m256_add_p(m, m, s)

    m256_mul_p(u, y, y)
    m256_add_p(u, u, u)
    m256_mul_p(s, x, u)
    m256_add_p(s, s, s)

    m256_mul_p(u, u, u)
    m256_add_p(u, u, u)

    m256_mul_p(x, m, m)
    m256_sub_p(x, x, s)
    m256_sub_p(x, x, s)

    m256_mul_p(z, y, z)
    m256_add_p(z, z, z)

    m256_sub_p(y, s, x)
    m256_mul_p(y, y, m)
    m256_sub_p(y, y, u)


def point_add(x1: list[uint32], y1: list[uint32], z1: list[uint32], x2: list[uint32], y2: list[uint32]) -> None:
    t1 = [uint32(0) for _ in range(8)]
    t2 = [uint32(0) for _ in range(8)]
    t3 = [uint32(0) for _ in range(8)]

    m256_mul_p(t1, z1, z1)
    m256_mul_p(t2, t1, z1)
    m256_mul_p(t1, t1, x2)

    m256_mul_p(t2, t2, y2)

    m256_sub_p(t1, t1, x1)

    m256_sub_p(t2, t2, y1)

    m256_mul_p(z1, z1, t1)

    m256_mul_p(t3, t1, t1)
    m256_mul_p(t1, t3, t1)

    m256_mul_p(t3, t3, x1)

    m256_mul_p(x1, t2, t2)
    m256_sub_p(x1, x1, t3)
    m256_sub_p(x1, x1, t3)
    m256_sub_p(x1, x1, t1)

    m256_sub_p(t3, t3, x1)
    m256_mul_p(t3, t3, t2)
    m256_mul_p(t1, t1, y1)
    m256_sub_p(y1, t3, t1)


def m256_inv(z: list[uint32], x: list[uint32], mod: type[p256_p] | type[p256_n]) -> None:
    bitval = [uint32(0) for _ in range(8)]
    u256_cmov(bitval, x, uint32(1))

    m256_set32(z, uint32(1), mod)

    i = 0
    limb = mod.m[i] - 2
    while True:
        for j in range(32):
            if (limb & 1) != 0:
                m256_mul(z, z, bitval, mod)
            m256_mul(bitval, bitval, bitval, mod)
            limb >>= 1

        if i == 7:
            break

        i += 1
        limb = mod.m[i]


def point_to_affine(x: list[uint32], y: list[uint32], z: list[uint32]) -> None:
    t = [uint32(0) for _ in range(8)]

    m256_inv(z, z, p256_p)

    m256_mul_p(t, z, z)
    m256_mul_p(x, x, t)

    m256_mul_p(t, t, z)
    m256_mul_p(y, y, t)


def m256_done(z: list[uint32], mod: type[p256_p] | type[p256_n]) -> None:
    one = [uint32(0) for _ in range(8)]
    u256_set32(one, uint32(1))
    m256_mul(z, z, one, mod)


def u256_to_bytes(p: list[uint8], z: list[uint32]) -> None:
    for i in range(8):
        j = 4 * (7 - i)
        p[j + 0] = uint8(z[i] >> 24)
        p[j + 1] = uint8(z[i] >> 16)
        p[j + 2] = uint8(z[i] >> 8)
        p[j + 3] = uint8(z[i] >> 0)


def m256_to_bytes(p: list[uint8], z: list[uint32], mod: type[p256_p] | type[p256_n]) -> None:
    zi = [uint32(0) for _ in range(8)]
    u256_cmov(zi, z, uint32(1))
    m256_done(zi, mod)

    u256_to_bytes(p, zi)


def u256_from_bytes(z: list[uint32], p: list[uint8]) -> None:
    for i in range(8):
        j = 4 * (7 - i)
        z[i] = (uint32(p[j + 0]) << 24 |
                uint32(p[j + 1]) << 16 |
                uint32(p[j + 2]) << 8 |
                uint32(p[j + 3]) << 0)


def scalar_from_bytes(s: list[uint32], p: list[uint8]) -> int:
    u256_from_bytes(s, p)

    r = [uint32(0) for _ in range(8)]
    lt_n = u256_sub(r, s, p256_n.m)

    u256_set32(r, uint32(1))
    lt_1 = u256_sub(r, s, r)

    if lt_n and not lt_1:
        return 0

    return -1


def m256_from_bytes(z: list[uint32], p: list[uint8], mod: type[p256_p] | type[p256_n]) -> int:
    u256_from_bytes(z, p)

    t = [uint32(0) for _ in range(8)]
    lt_m = u256_sub(t, z, mod.m)

    if lt_m != 1:
        return -1

    m256_prep(z, mod)
    return 0

def u256_diff(x: list[uint32], y: list[uint32]) -> uint32:
    diff = uint32(0)

    for i in range(8):
        diff |= x[i] ^ y[i]

    return diff


def point_check(x: list[uint32], y: list[uint32]) -> uint32:
    lhs = [uint32(0) for _ in range(8)]
    rhs = [uint32(0) for _ in range(8)]

    m256_mul_p(lhs, y, y)

    m256_mul_p(rhs, x, x)
    m256_mul_p(rhs, rhs, x)

    for i in range(3):
        m256_sub_p(rhs, rhs, x)

    m256_add_p(rhs, rhs, p256_b)

    return u256_diff(lhs, rhs)


def point_from_bytes(x: list[uint32], y: list[uint32], p: list[uint8]) -> int:

    ret = m256_from_bytes(x, p, p256_p)
    if ret != 0:
        return ret

    ret = m256_from_bytes(y, p[32:], p256_p)
    if ret != 0:
        return ret

    return int(point_check(x, y))
