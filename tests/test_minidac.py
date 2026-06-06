import unittest

from minidac.crypto import RSAKeypair, blind_token_request, blind_sign, unblind_signature, rsa_verify
from minidac.model import build_system


class MiniDACTest(unittest.TestCase):
    def test_baseline_and_selective_disclosure_agree(self):
        _, verifier, holders, credentials, policies = build_system()
        for holder in holders:
            for policy in policies:
                baseline = verifier.baseline(holder, policy)
                sd = verifier.selective_disclosure(holder, credentials[holder.user_id], policy)
                self.assertTrue(sd.verified)
                self.assertEqual(baseline.allowed, sd.allowed)

    def test_revoked_credential_cannot_mint_token(self):
        issuer, verifier, holders, credentials, policies = build_system()
        holder = holders[0]
        issuer.revoke(credentials[holder.user_id].credential_id)
        result = verifier.blind_token(holder, credentials[holder.user_id], policies[0])
        self.assertFalse(result.allowed)

    def test_blind_rsa_roundtrip(self):
        key = RSAKeypair.deterministic(seed=12345, bits=1024)
        req = blind_token_request("demo_policy", key.n, key.e)
        blind_sig = blind_sign(req.blinded, key)
        sig = unblind_signature(blind_sig, req.blind_factor, key.n)
        self.assertTrue(rsa_verify(req.message, sig, key.n, key.e))


if __name__ == "__main__":
    unittest.main()

