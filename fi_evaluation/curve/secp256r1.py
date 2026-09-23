from cryptography.hazmat.primitives.asymmetric import ec

from fi_evaluation.curve import Curve


class SECP256R1(Curve):

    name = 'secp256r1'
    _base_point = bytes.fromhex('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')

    def base_point(self) -> bytes:
        return SECP256R1._base_point

    def shared_secret(self, public_key_bytes: bytes, private_key_bytes: bytes) -> bytes:
        try:
            private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, 'big'), ec.SECP256R1())
        except ValueError as exc:
            raise ValueError(f"Invalid private key for secp256r1 curve {private_key_bytes.hex()}.") from exc

        if len(public_key_bytes) == 64:
            # The library expects the "uncompressed key" prefix (0x04)
            public_key_bytes = b'\x04' + public_key_bytes

        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)
        shared_secret_bytes = private_key.exchange(ec.ECDH(), public_key)
        return shared_secret_bytes
