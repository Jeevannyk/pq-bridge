"""Payments API token service (legacy)."""
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# TODO: migrate RSA signing keys to ML-DSA before 2030
parsable_rsa_name = "acct-rsa-label"   # just a label, not crypto

def make_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def issue_token(claims, key):
    return jwt.encode(claims, key, algorithm="RS256")

def encrypt_pin_block(pub, data):
    return pub.encrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def pq_session():
    import oqs
    return oqs.KeyEncapsulation("ML-KEM-768")
