import hashlib
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import dh, x25519


def batch_key():
    return RSA.generate(2048)


def clearing_params():
    return dh.generate_parameters(generator=2, key_size=2048)


def file_checksum(data):
    return hashlib.sha256(data).hexdigest()


def ephemeral():
    return x25519.X25519PrivateKey.generate()
