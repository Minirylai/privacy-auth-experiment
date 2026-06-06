"""Protocol model for the minimal-disclosure authentication experiment."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .crypto import (
    RSAKeypair,
    BlindRequest,
    canonical_json,
    hash_leaf,
    merkle_root,
    rsa_sign,
    rsa_verify,
    blind_token_request,
    blind_sign,
    unblind_signature,
    schnorr_keygen,
    schnorr_prove,
    schnorr_verify,
)


SENSITIVE_FIELDS = {"name", "student_id", "id_number", "email", "project_id"}

FIELD_BITS = {
    "name": 24,
    "student_id": 32,
    "id_number": 64,
    "email": 48,
    "role": 4,
    "department": 8,
    "project_id": 16,
    "training_completed": 1,
    "age_over_18": 1,
    "authorization_level": 3,
    "credential_status": 2,
    "expires_at": 16,
    "role_student": 1,
    "department_cyber": 1,
}


@dataclass(frozen=True)
class Policy:
    name: str
    conditions: Dict[str, Any]

    def evaluate(self, attrs: Dict[str, Any]) -> bool:
        for key, expected in self.conditions.items():
            actual = attrs.get(key)
            if isinstance(expected, dict):
                if "gte" in expected and not (actual >= expected["gte"]):
                    return False
                if "lte" in expected and not (actual <= expected["lte"]):
                    return False
                if "in" in expected and actual not in expected["in"]:
                    return False
            elif actual != expected:
                return False
        return True


@dataclass
class Holder:
    user_id: str
    attributes: Dict[str, Any]
    secret: int
    public: int

    @classmethod
    def from_attributes(cls, user_id: str, attributes: Dict[str, Any]) -> "Holder":
        kp = schnorr_keygen()
        return cls(user_id=user_id, attributes=attributes, secret=kp.secret, public=kp.public)


@dataclass
class Credential:
    credential_id: str
    issuer: str
    holder_public: int
    root: str
    leaves: Dict[str, str]
    salts: Dict[str, str]
    signature: int
    expires_at: str

    def signed_payload(self) -> bytes:
        return canonical_json(
            {
                "credential_id": self.credential_id,
                "issuer": self.issuer,
                "holder_public": str(self.holder_public),
                "root": self.root,
                "expires_at": self.expires_at,
            }
        )


@dataclass
class PresentationResult:
    mode: str
    allowed: bool
    verified: bool
    exposed_fields: List[str]
    personal_leakage_bits: int
    protocol_metadata_bits: int
    linkability_handle: str | None
    elapsed_ms: float
    notes: List[str] = field(default_factory=list)


class Issuer:
    def __init__(self, name: str, signing_key: RSAKeypair, token_key: RSAKeypair):
        self.name = name
        self.signing_key = signing_key
        self.token_key = token_key
        self.revoked_credentials: set[str] = set()
        self.issuance_log: list[int] = []

    def issue(self, holder: Holder) -> Credential:
        salts = {k: f"salt-{holder.user_id}-{k}" for k in holder.attributes}
        leaves = {k: hash_leaf(k, v, salts[k]) for k, v in sorted(holder.attributes.items())}
        root = merkle_root(leaves[k] for k in sorted(leaves))
        credential_id = f"cred-{holder.user_id}"
        credential = Credential(
            credential_id=credential_id,
            issuer=self.name,
            holder_public=holder.public,
            root=root,
            leaves=leaves,
            salts=salts,
            signature=0,
            expires_at=str(holder.attributes.get("expires_at", "2026-12-31")),
        )
        credential.signature = rsa_sign(credential.signed_payload(), self.signing_key)
        return credential

    def revoke(self, credential_id: str) -> None:
        self.revoked_credentials.add(credential_id)

    def verify_credential_for_issuance(self, credential: Credential, holder: Holder, policy: Policy) -> bool:
        if credential.credential_id in self.revoked_credentials:
            return False
        if not rsa_verify(credential.signed_payload(), credential.signature, self.signing_key.n, self.signing_key.e):
            return False
        if credential.holder_public != holder.public:
            return False
        return policy.evaluate(holder.attributes)

    def blind_issue_token(self, credential: Credential, holder: Holder, policy: Policy, blinded: int) -> int | None:
        if not self.verify_credential_for_issuance(credential, holder, policy):
            return None
        self.issuance_log.append(blinded)
        return blind_sign(blinded, self.token_key)


class Verifier:
    def __init__(self, issuer: Issuer):
        self.issuer = issuer
        self.spent_tokens: set[str] = set()

    def baseline(self, holder: Holder, policy: Policy) -> PresentationResult:
        start = time.perf_counter()
        allowed = policy.evaluate(holder.attributes)
        exposed = sorted(holder.attributes.keys())
        leakage = sum(FIELD_BITS.get(k, 8) for k in exposed)
        return PresentationResult(
            mode="baseline-full-identity",
            allowed=allowed,
            verified=True,
            exposed_fields=exposed,
            personal_leakage_bits=leakage,
            protocol_metadata_bits=0,
            linkability_handle=holder.user_id,
            elapsed_ms=(time.perf_counter() - start) * 1000,
        )

    def selective_disclosure(self, holder: Holder, credential: Credential, policy: Policy) -> PresentationResult:
        start = time.perf_counter()
        verified = rsa_verify(
            credential.signed_payload(),
            credential.signature,
            self.issuer.signing_key.n,
            self.issuer.signing_key.e,
        )
        exposed = sorted(policy.conditions.keys())
        disclosed = {k: holder.attributes[k] for k in exposed}
        recomputed = {
            k: hash_leaf(k, holder.attributes[k], credential.salts[k])
            for k in holder.attributes
        }
        root_ok = merkle_root(recomputed[k] for k in sorted(recomputed)) == credential.root
        challenge = canonical_json({"policy": policy.name, "root": credential.root})
        proof = schnorr_prove(holder.secret, holder.public, challenge)
        holder_ok = schnorr_verify(holder.public, challenge, proof)
        allowed = policy.evaluate(disclosed)
        leakage = sum(FIELD_BITS.get(k, 8) for k in exposed)
        notes = []
        if credential.root:
            notes.append("credential root is stable and linkable across presentations")
        return PresentationResult(
            mode="selective-disclosure-merkle-vc",
            allowed=allowed,
            verified=verified and root_ok and holder_ok,
            exposed_fields=exposed + ["credential_root"],
            personal_leakage_bits=leakage,
            protocol_metadata_bits=256,
            linkability_handle=credential.root,
            elapsed_ms=(time.perf_counter() - start) * 1000,
            notes=notes,
        )

    def blind_token(self, holder: Holder, credential: Credential, policy: Policy) -> PresentationResult:
        start = time.perf_counter()
        req = blind_token_request(policy.name, self.issuer.token_key.n, self.issuer.token_key.e)
        blind_sig = self.issuer.blind_issue_token(credential, holder, policy, req.blinded)
        if blind_sig is None:
            return PresentationResult(
                mode="blind-token-minimal-disclosure",
                allowed=False,
                verified=True,
                exposed_fields=[],
                personal_leakage_bits=1,
                protocol_metadata_bits=0,
                linkability_handle=None,
                elapsed_ms=(time.perf_counter() - start) * 1000,
                notes=["issuer refused token because policy failed or credential was revoked"],
            )
        signature = unblind_signature(blind_sig, req.blind_factor, self.issuer.token_key.n)
        token_id = req.token
        token_ok = rsa_verify(req.message, signature, self.issuer.token_key.n, self.issuer.token_key.e)
        replay_ok = token_id not in self.spent_tokens
        self.spent_tokens.add(token_id)
        return PresentationResult(
            mode="blind-token-minimal-disclosure",
            allowed=token_ok and replay_ok,
            verified=token_ok and replay_ok,
            exposed_fields=["policy_satisfied_bit", "single_use_token"],
            personal_leakage_bits=1,
            protocol_metadata_bits=256,
            linkability_handle=None,
            elapsed_ms=(time.perf_counter() - start) * 1000,
            notes=["token issuance and redemption are unlinkable in this toy blind-signature flow"],
        )


def make_default_holders() -> list[Holder]:
    raw = [
        {
            "user_id": "U001",
            "name": "Alice",
            "student_id": "255001",
            "id_number": "320000199901010001",
            "email": "alice@example.edu",
            "role": "student",
            "role_student": True,
            "department": "网络空间安全学院",
            "department_cyber": True,
            "project_id": "P-ZK-01",
            "training_completed": True,
            "age_over_18": True,
            "authorization_level": 3,
            "credential_status": "valid",
            "expires_at": "2026-12-31",
        },
        {
            "user_id": "U002",
            "name": "Bob",
            "student_id": "255002",
            "id_number": "320000200801010002",
            "email": "bob@example.edu",
            "role": "student",
            "role_student": True,
            "department": "数学学院",
            "department_cyber": False,
            "project_id": "P-MATH",
            "training_completed": True,
            "age_over_18": False,
            "authorization_level": 1,
            "credential_status": "valid",
            "expires_at": "2026-12-31",
        },
        {
            "user_id": "U003",
            "name": "Carol",
            "student_id": "255003",
            "id_number": "320000199802020003",
            "email": "carol@example.edu",
            "role": "researcher",
            "role_student": False,
            "department": "网络空间安全学院",
            "department_cyber": True,
            "project_id": "P-ZK-01",
            "training_completed": True,
            "age_over_18": True,
            "authorization_level": 4,
            "credential_status": "valid",
            "expires_at": "2026-12-31",
        },
        {
            "user_id": "U004",
            "name": "Dave",
            "student_id": "255004",
            "id_number": "320000199703030004",
            "email": "dave@example.edu",
            "role": "student",
            "role_student": True,
            "department": "网络空间安全学院",
            "department_cyber": True,
            "project_id": "P-ZK-02",
            "training_completed": False,
            "age_over_18": True,
            "authorization_level": 2,
            "credential_status": "valid",
            "expires_at": "2026-12-31",
        },
    ]
    return [Holder.from_attributes(x["user_id"], {k: v for k, v in x.items() if k != "user_id"}) for x in raw]


def make_default_policies() -> list[Policy]:
    return [
        Policy("student_basic", {"role_student": True}),
        Policy("trained_adult_student", {"role_student": True, "training_completed": True, "age_over_18": True}),
        Policy("cyber_project_level2", {"department_cyber": True, "authorization_level": {"gte": 2}}),
    ]


def build_system() -> tuple[Issuer, Verifier, list[Holder], dict[str, Credential], list[Policy]]:
    issuer = Issuer(
        "Southeast-University-Demo-Issuer",
        signing_key=RSAKeypair.deterministic(seed=20260606, bits=1024),
        token_key=RSAKeypair.deterministic(seed=20260608, bits=1024),
    )
    verifier = Verifier(issuer)
    holders = make_default_holders()
    credentials = {h.user_id: issuer.issue(h) for h in holders}
    policies = make_default_policies()
    return issuer, verifier, holders, credentials, policies
