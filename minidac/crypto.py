"""Small cryptographic building blocks for the teaching prototype.

The code in this file is intentionally compact and dependency-free. It is meant
for reproducible course experiments, not for production.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import secrets
from dataclasses import dataclass
from typing import Iterable


RFC3526_2048_P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""

P = int("".join(RFC3526_2048_P_HEX.split()), 16)
Q = (P - 1) // 2
G = 2


def sha256_bytes(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(len(part).to_bytes(4, "big"))
        h.update(part)
    return h.digest()


def sha256_int(*parts: bytes) -> int:
    return int.from_bytes(sha256_bytes(*parts), "big")


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def int_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def hash_leaf(name: str, value: object, salt: str) -> str:
    payload = canonical_json({"name": name, "value": value, "salt": salt})
    return sha256_bytes(b"leaf", payload).hex()


def merkle_root(leaves: Iterable[str]) -> str:
    layer = [bytes.fromhex(x) for x in leaves]
    if not layer:
        return sha256_bytes(b"empty").hex()
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        nxt = []
        for i in range(0, len(layer), 2):
            left, right = sorted([layer[i], layer[i + 1]])
            nxt.append(sha256_bytes(b"node", left, right))
        layer = nxt
    return layer[0].hex()


@dataclass(frozen=True)
class SchnorrKeypair:
    secret: int
    public: int


@dataclass(frozen=True)
class SchnorrProof:
    commitment: int
    challenge: int
    response: int


def schnorr_keygen(rng: random.Random | None = None) -> SchnorrKeypair:
    rng = rng or random.SystemRandom()
    secret = rng.randrange(2, Q - 1)
    return SchnorrKeypair(secret=secret, public=pow(G, secret, P))


def schnorr_prove(secret: int, public: int, message: bytes, rng: random.Random | None = None) -> SchnorrProof:
    rng = rng or random.SystemRandom()
    nonce = rng.randrange(2, Q - 1)
    commitment = pow(G, nonce, P)
    challenge = sha256_int(int_bytes(commitment), int_bytes(public), message) % Q
    response = (nonce + challenge * secret) % Q
    return SchnorrProof(commitment, challenge, response)


def schnorr_verify(public: int, message: bytes, proof: SchnorrProof) -> bool:
    left = pow(G, proof.response, P)
    inv = pow(pow(public, proof.challenge, P), P - 2, P)
    commitment_prime = (left * inv) % P
    challenge_prime = sha256_int(int_bytes(commitment_prime), int_bytes(public), message) % Q
    return challenge_prime == proof.challenge


def is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    rng = random.Random(n)
    for _ in range(rounds):
        a = rng.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def deterministic_prime(seed: int, bits: int) -> int:
    rng = random.Random(seed)
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n


@dataclass(frozen=True)
class RSAKeypair:
    n: int
    e: int
    d: int

    @classmethod
    def deterministic(cls, seed: int = 20260606, bits: int = 1024) -> "RSAKeypair":
        e = 65537
        half = bits // 2
        p = deterministic_prime(seed, half)
        q = deterministic_prime(seed + 1, half)
        while p == q:
            q = deterministic_prime(seed + 2, half)
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            return cls.deterministic(seed + 10, bits)
        d = pow(e, -1, phi)
        return cls(n=p * q, e=e, d=d)


def rsa_message_int(message: bytes, n: int) -> int:
    return sha256_int(b"rsa-fdh", message) % n


def rsa_sign(message: bytes, key: RSAKeypair) -> int:
    return pow(rsa_message_int(message, key.n), key.d, key.n)


def rsa_verify(message: bytes, signature: int, n: int, e: int) -> bool:
    return pow(signature, e, n) == rsa_message_int(message, n)


@dataclass(frozen=True)
class BlindRequest:
    token: str
    message: bytes
    blinded: int
    blind_factor: int


def blind_token_request(policy_name: str, n: int, e: int) -> BlindRequest:
    token = secrets.token_hex(32)
    message = canonical_json({"policy": policy_name, "token": token})
    m = rsa_message_int(message, n)
    while True:
        r = secrets.randbelow(n - 2) + 2
        if math.gcd(r, n) == 1:
            break
    blinded = (m * pow(r, e, n)) % n
    return BlindRequest(token=token, message=message, blinded=blinded, blind_factor=r)


def blind_sign(blinded: int, key: RSAKeypair) -> int:
    return pow(blinded, key.d, key.n)


def unblind_signature(blind_signature: int, blind_factor: int, n: int) -> int:
    return (blind_signature * pow(blind_factor, -1, n)) % n

