"""Reproducible experiment runner."""

from __future__ import annotations

import json
import statistics
from pathlib import Path

from .model import build_system, Policy, PresentationResult


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def summarize(results: list[PresentationResult]) -> dict:
    by_mode: dict[str, list[PresentationResult]] = {}
    for item in results:
        by_mode.setdefault(item.mode, []).append(item)
    summary = {}
    for mode, items in by_mode.items():
        summary[mode] = {
            "runs": len(items),
            "verified": sum(1 for x in items if x.verified),
            "allowed": sum(1 for x in items if x.allowed),
            "median_latency_ms": round(statistics.median(x.elapsed_ms for x in items), 4),
            "mean_personal_leakage_bits": round(statistics.mean(x.personal_leakage_bits for x in items), 2),
            "mean_protocol_metadata_bits": round(statistics.mean(x.protocol_metadata_bits for x in items), 2),
            "mean_exposed_fields": round(statistics.mean(len(x.exposed_fields) for x in items), 2),
            "linkable_presentations": sum(1 for x in items if x.linkability_handle is not None),
        }
    return summary


def correctness_matrix(raw: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str], dict[str, bool]] = {}
    for row in raw:
        key = (row["user_id"], row["policy"])
        grouped.setdefault(key, {})[row["mode"]] = row["allowed"]
    matrix = []
    for (user_id, policy), decisions in sorted(grouped.items()):
        matrix.append(
            {
                "user_id": user_id,
                "policy": policy,
                "decisions": decisions,
                "consistent": len(set(decisions.values())) == 1,
            }
        )
    return matrix


def result_to_row(user_id: str, policy: Policy, result: PresentationResult) -> dict:
    return {
        "user_id": user_id,
        "policy": policy.name,
        "mode": result.mode,
        "allowed": result.allowed,
        "verified": result.verified,
        "exposed_fields": result.exposed_fields,
        "personal_leakage_bits": result.personal_leakage_bits,
        "protocol_metadata_bits": result.protocol_metadata_bits,
        "linkability_handle": result.linkability_handle,
        "elapsed_ms": round(result.elapsed_ms, 4),
        "notes": result.notes,
    }


def write_report(payload: dict) -> None:
    lines = [
        "# Minimal-Disclosure Authentication Experiment Report",
        "",
        "## Summary by Mode",
        "",
        "| Mode | Runs | Verified | Allowed | Median latency (ms) | Mean personal leakage (bits) | Mean protocol metadata (bits) | Mean exposed fields | Linkable presentations |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for mode, row in payload["summary_by_mode"].items():
        lines.append(
            f"| {mode} | {row['runs']} | {row['verified']} | {row['allowed']} | "
            f"{row['median_latency_ms']} | {row['mean_personal_leakage_bits']} | "
            f"{row['mean_protocol_metadata_bits']} | "
            f"{row['mean_exposed_fields']} | {row['linkable_presentations']} |"
        )
    lines.extend(
        [
            "",
            "## Correctness Matrix",
            "",
            "| User | Policy | Consistent allow/deny decisions |",
            "| --- | --- | --- |",
        ]
    )
    for row in payload["correctness_matrix"]:
        lines.append(f"| {row['user_id']} | {row['policy']} | {row['consistent']} |")
    lines.extend(
        [
            "",
            "## Revocation Check",
            "",
            f"- Revoked credential: `{payload['revocation_check']['revoked_credential']}`",
            f"- Token issuance after revocation allowed: `{payload['revocation_check']['allowed_after_revocation']}`",
            "",
            "## Notes",
            "",
            "- Selective-disclosure Merkle credentials reduce field exposure but reveal a stable root.",
            "- Blind tokens reveal only policy satisfaction at redemption time, but support only coarse policy classes.",
            "- Numbers are Python local measurements for a teaching prototype, not production ZKP timings.",
        ]
    )
    (RESULTS / "report.md").write_text("\n".join(lines), encoding="utf-8")


def run_all_experiments() -> dict:
    RESULTS.mkdir(exist_ok=True)
    issuer, verifier, holders, credentials, policies = build_system()

    raw_rows = []
    presentation_results = []
    for holder in holders:
        credential = credentials[holder.user_id]
        for policy in policies:
            for result in [
                verifier.baseline(holder, policy),
                verifier.selective_disclosure(holder, credential, policy),
                verifier.blind_token(holder, credential, policy),
            ]:
                raw_rows.append(result_to_row(holder.user_id, policy, result))
                presentation_results.append(result)

    revoked_holder = holders[0]
    issuer.revoke(credentials[revoked_holder.user_id].credential_id)
    revoked_result = verifier.blind_token(revoked_holder, credentials[revoked_holder.user_id], policies[0])

    payload = {
        "summary_by_mode": summarize(presentation_results),
        "correctness_matrix": correctness_matrix(raw_rows),
        "rows": raw_rows,
        "revocation_check": {
            "revoked_credential": credentials[revoked_holder.user_id].credential_id,
            "allowed_after_revocation": revoked_result.allowed,
            "verified": revoked_result.verified,
            "notes": revoked_result.notes,
        },
        "issuer_blinded_values_seen": len(issuer.issuance_log),
    }
    (RESULTS / "summary.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_report(payload)

    print("Experiment finished.")
    print(f"Wrote {RESULTS / 'summary.json'}")
    print(f"Wrote {RESULTS / 'report.md'}")
    for mode, row in payload["summary_by_mode"].items():
        print(
            f"- {mode}: median={row['median_latency_ms']} ms, "
            f"personal_leakage={row['mean_personal_leakage_bits']} bits, "
            f"metadata={row['mean_protocol_metadata_bits']} bits, "
            f"linkable={row['linkable_presentations']}/{row['runs']}"
        )
    print(f"Revocation blocks token issuance: {not payload['revocation_check']['allowed_after_revocation']}")
    return payload
