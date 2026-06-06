#!/usr/bin/env python3
"""Generate publication-style figures for the course paper.

This script is intentionally separate from `plot_results.py`. The normal
experiment remains dependency-free; this script uses matplotlib/seaborn only to
produce nicer figures for the LaTeX paper.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import pandas as pd
import seaborn as sns


ROOT = Path(__file__).resolve().parent
SUMMARY = ROOT / "results" / "summary.json"
OUT = ROOT / "results" / "publication_figures"

MODE_ORDER = [
    "baseline-full-identity",
    "selective-disclosure-merkle-vc",
    "blind-token-minimal-disclosure",
]
MODE_LABEL = {
    "baseline-full-identity": "Baseline\nfull identity",
    "selective-disclosure-merkle-vc": "Merkle selective\ndisclosure",
    "blind-token-minimal-disclosure": "Blind token\nminimal disclosure",
}
MODE_SHORT = {
    "baseline-full-identity": "Baseline",
    "selective-disclosure-merkle-vc": "Merkle SD",
    "blind-token-minimal-disclosure": "Blind Token",
}

PALETTE = {
    "baseline-full-identity": "#D55E00",
    "selective-disclosure-merkle-vc": "#009E73",
    "blind-token-minimal-disclosure": "#0072B2",
    "metadata": "#7B61FF",
    "linkability": "#CC79A7",
    "neutral": "#4D4D4D",
    "light": "#F5F7FA",
}


def setup_style() -> None:
    sns.set_theme(style="whitegrid", context="paper", font_scale=1.25)
    plt.rcParams["font.sans-serif"] = [
        "Microsoft YaHei",
        "SimHei",
        "Arial Unicode MS",
        "DejaVu Sans",
    ]
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["font.size"] = 10.5
    plt.rcParams["axes.labelsize"] = 11
    plt.rcParams["xtick.labelsize"] = 10
    plt.rcParams["ytick.labelsize"] = 10
    plt.rcParams["legend.fontsize"] = 10
    plt.rcParams["figure.dpi"] = 150
    plt.rcParams["savefig.dpi"] = 320
    plt.rcParams["pdf.fonttype"] = 42
    plt.rcParams["svg.fonttype"] = "none"


def load_summary() -> dict:
    return json.loads(SUMMARY.read_text(encoding="utf-8"))


def savefig(fig: plt.Figure, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for ext in ["png", "svg", "pdf"]:
        fig.savefig(OUT / f"{name}.{ext}", bbox_inches="tight", facecolor="white")
    plt.close(fig)


def add_box(ax, xy, wh, text, fc="#FFFFFF", ec="#333333", lw=1.4, fontsize=11):
    box = patches.FancyBboxPatch(
        xy,
        wh[0],
        wh[1],
        boxstyle="round,pad=0.025,rounding_size=0.035",
        linewidth=lw,
        edgecolor=ec,
        facecolor=fc,
    )
    ax.add_patch(box)
    ax.text(
        xy[0] + wh[0] / 2,
        xy[1] + wh[1] / 2,
        text,
        ha="center",
        va="center",
        fontsize=fontsize,
        color="#222222",
        weight="semibold",
    )


def arrow(ax, start, end, text="", rad=0.0, color="#3A3A3A"):
    arr = patches.FancyArrowPatch(
        start,
        end,
        arrowstyle="-|>",
        mutation_scale=14,
        linewidth=1.4,
        color=color,
        connectionstyle=f"arc3,rad={rad}",
    )
    ax.add_patch(arr)
    if text:
        mx, my = (start[0] + end[0]) / 2, (start[1] + end[1]) / 2
        ax.text(mx, my + 0.035, text, ha="center", va="bottom", fontsize=9.5, color=color)


def fig_framework() -> None:
    fig, ax = plt.subplots(figsize=(11.5, 6.4))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    add_box(ax, (0.08, 0.58), (0.22, 0.18), "Issuer\nattribute credential\nrevocation state", "#E8F5E9", "#009E73")
    add_box(ax, (0.39, 0.58), (0.22, 0.18), "Holder wallet\nattributes\nprivate key", "#E3F2FD", "#0072B2")
    add_box(ax, (0.70, 0.58), (0.22, 0.18), "Verifier\ndata service\naccess policy", "#FFF3E0", "#D55E00")
    add_box(ax, (0.22, 0.20), (0.22, 0.15), "Public registry\nkeys / policies\nrevocation list", "#F6F4FF", "#7B61FF")
    add_box(ax, (0.58, 0.20), (0.22, 0.15), "Auditor\nmulti-party\naccountability", "#FCE4EC", "#CC79A7")

    arrow(ax, (0.30, 0.67), (0.39, 0.67), "issue credential")
    arrow(ax, (0.61, 0.67), (0.70, 0.67), "proof / token")
    arrow(ax, (0.19, 0.58), (0.30, 0.35), "publish keys", rad=-0.08, color="#7B61FF")
    arrow(ax, (0.81, 0.58), (0.69, 0.35), "policy version", rad=0.08, color="#7B61FF")
    arrow(ax, (0.79, 0.58), (0.69, 0.35), "minimal log", rad=-0.12, color="#CC79A7")
    arrow(ax, (0.58, 0.28), (0.44, 0.28), "authorized audit", color="#CC79A7")

    ax.text(
        0.5,
        0.06,
        "Design goal: the verifier learns policy satisfaction, not the user's full identity profile.",
        ha="center",
        fontsize=11,
        color="#444444",
    )
    savefig(fig, "fig5_framework")


def fig_protocol_sequence() -> None:
    fig, ax = plt.subplots(figsize=(12, 6.6))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    xs = [0.16, 0.50, 0.84]
    names = ["Holder", "Issuer", "Verifier"]
    colors = ["#E3F2FD", "#E8F5E9", "#FFF3E0"]
    edges = ["#0072B2", "#009E73", "#D55E00"]
    for x, name, fc, ec in zip(xs, names, colors, edges):
        add_box(ax, (x - 0.09, 0.82), (0.18, 0.10), name, fc, ec, fontsize=12)
        ax.plot([x, x], [0.15, 0.82], color="#B0B0B0", linestyle="--", linewidth=1.2)

    steps = [
        (0.76, xs[1], xs[0], "1. signed credential root"),
        (0.66, xs[2], xs[0], "2. access policy"),
        (0.56, xs[0], xs[2], "3a. full attributes (baseline)"),
        (0.46, xs[0], xs[2], "3b. disclosed fields + Schnorr proof"),
        (0.36, xs[0], xs[1], "3c. blind token request"),
        (0.28, xs[1], xs[0], "4. blind signature / refusal"),
        (0.20, xs[0], xs[2], "5. redeem unblinded token"),
    ]
    for y, x1, x2, label in steps:
        arrow(ax, (x1, y), (x2, y), label, color="#333333")
    savefig(fig, "fig6_protocol_sequence")


def fig_revocation_flow() -> None:
    fig, ax = plt.subplots(figsize=(11.5, 4.9))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    nodes = [
        ((0.04, 0.50), (0.15, 0.15), "Blind token\nrequest", "#E3F2FD", "#0072B2"),
        ((0.25, 0.50), (0.15, 0.15), "Signature\nvalid?", "#FFFFFF", "#666666"),
        ((0.46, 0.50), (0.15, 0.15), "Credential\nrevoked?", "#FFFFFF", "#666666"),
        ((0.67, 0.50), (0.15, 0.15), "Policy\nsatisfied?", "#FFFFFF", "#666666"),
        ((0.85, 0.64), (0.12, 0.12), "Return\nblind sig", "#E8F5E9", "#009E73"),
        ((0.85, 0.34), (0.12, 0.12), "Refuse\nissuance", "#FCE4EC", "#CC79A7"),
    ]
    for xy, wh, text, fc, ec in nodes:
        add_box(ax, xy, wh, text, fc, ec, fontsize=10.5)
    arrow(ax, (0.19, 0.575), (0.25, 0.575), "yes")
    arrow(ax, (0.40, 0.575), (0.46, 0.575), "yes")
    arrow(ax, (0.61, 0.575), (0.67, 0.575), "no")
    arrow(ax, (0.82, 0.62), (0.85, 0.70), "yes", color="#009E73")
    arrow(ax, (0.325, 0.50), (0.87, 0.46), "no", rad=0.25, color="#CC79A7")
    arrow(ax, (0.535, 0.50), (0.87, 0.46), "yes", rad=0.12, color="#CC79A7")
    arrow(ax, (0.745, 0.50), (0.87, 0.46), "no", rad=0.0, color="#CC79A7")
    savefig(fig, "fig6_revocation_flow")


def metric_dataframe(summary: dict) -> pd.DataFrame:
    rows = []
    for key in MODE_ORDER:
        row = summary["summary_by_mode"][key]
        rows.append(
            {
                "mode": MODE_SHORT[key],
                "key": key,
                "Personal leakage (bits)": row["mean_personal_leakage_bits"],
                "Protocol metadata (bits)": row["mean_protocol_metadata_bits"],
                "Exposed fields": row["mean_exposed_fields"],
                "Linkable presentations": row["linkable_presentations"],
                "Median runtime (ms)": row["median_latency_ms"],
            }
        )
    return pd.DataFrame(rows)


def fig_metric_dashboard(summary: dict) -> None:
    df = metric_dataframe(summary)
    fig, axes = plt.subplots(2, 2, figsize=(12.5, 8.4))

    specs = [
        ("Personal leakage (bits)", axes[0, 0], "(a)", False),
        ("Exposed fields", axes[0, 1], "(b)", False),
        ("Linkable presentations", axes[1, 0], "(c)", False),
        ("Median runtime (ms)", axes[1, 1], "(d)", True),
    ]
    colors = [PALETTE[k] for k in MODE_ORDER]
    for metric, ax, panel, logy in specs:
        sns.barplot(data=df, x="mode", y=metric, ax=ax, palette=colors, hue="mode", legend=False)
        ax.set_xlabel("")
        ax.set_ylabel(metric)
        ax.text(-0.12, 1.04, panel, transform=ax.transAxes, fontsize=12, weight="bold", va="bottom")
        if logy:
            ax.set_yscale("log")
            ax.text(0.03, 0.92, "log scale", transform=ax.transAxes, fontsize=9, color="#555")
        for container in ax.containers:
            ax.bar_label(container, fmt="%.2g", padding=3, fontsize=9)
        ax.grid(axis="y", alpha=0.25)
    fig.tight_layout(rect=[0, 0.01, 1, 1])
    savefig(fig, "fig6_metric_dashboard")


def fig_leakage_metadata(summary: dict) -> None:
    df = metric_dataframe(summary)
    x = np.arange(len(df))
    width = 0.34
    fig, ax = plt.subplots(figsize=(10.8, 5.8))
    ax.bar(
        x - width / 2,
        df["Personal leakage (bits)"],
        width,
        label="personal attribute leakage",
        color="#0072B2",
    )
    ax.bar(
        x + width / 2,
        df["Protocol metadata (bits)"],
        width,
        label="protocol metadata",
        color="#7B61FF",
    )
    ax.set_xticks(x, df["mode"])
    ax.set_ylabel("estimated bits")
    ax.legend(frameon=False, loc="upper left")
    ax.grid(axis="y", alpha=0.25)
    for container in ax.containers:
        ax.bar_label(container, fmt="%.2f", padding=3, fontsize=9)
    ax.text(0.02, 0.96, "protocol handles are separated from personal attributes", transform=ax.transAxes, fontsize=9, color="#555", va="top")
    fig.tight_layout()
    savefig(fig, "fig6_leakage_metadata")


def fig_correctness_heatmap(summary: dict) -> None:
    rows = []
    for item in summary["correctness_matrix"]:
        for mode, decision in item["decisions"].items():
            rows.append(
                {
                    "case": f"{item['user_id']}\n{item['policy'].replace('_', ' ')}",
                    "mode": MODE_SHORT[mode],
                    "decision": int(decision),
                }
            )
    df = pd.DataFrame(rows)
    pivot = df.pivot(index="case", columns="mode", values="decision")
    pivot = pivot[[MODE_SHORT[k] for k in MODE_ORDER]]
    fig, ax = plt.subplots(figsize=(7.2, 8.8))
    sns.heatmap(
        pivot,
        annot=pivot.replace({0: "DENY", 1: "ALLOW"}),
        fmt="",
        cmap=sns.color_palette(["#FDE0DD", "#DDEEDB"], as_cmap=True),
        cbar=False,
        linewidths=0.8,
        linecolor="#FFFFFF",
        ax=ax,
    )
    ax.set_xlabel("")
    ax.set_ylabel("user-policy case")
    fig.tight_layout()
    savefig(fig, "fig6_correctness_heatmap")


def main() -> None:
    setup_style()
    summary = load_summary()
    fig_framework()
    fig_protocol_sequence()
    fig_revocation_flow()
    fig_metric_dashboard(summary)
    fig_leakage_metadata(summary)
    fig_correctness_heatmap(summary)
    print(f"Wrote publication figures to {OUT}")


if __name__ == "__main__":
    main()
