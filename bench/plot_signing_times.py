#!/usr/bin/env python3
"""Parse Go benchmark output and plot signing times (histogram with error bars).

Usage:
    python3 plot_signing_times.py [BENCH_RESULTS_FILE] [OUTPUT_FILE]

Defaults:
    BENCH_RESULTS_FILE = bench_results_100.txt
    OUTPUT_FILE        = signing_times.pdf

The script also prints a LaTeX-ready table to stdout.
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np


# ── Parse ──────────────────────────────────────────────────────────────

def parse_bench_file(path: str) -> dict[str, list[float]]:
    """Return {algorithm_name: [ns/op, ...]} from Go benchmark output."""
    pattern = re.compile(
        r"BenchmarkSign/(?P<name>[^\s-]+(?:-[^\s-]+)*)-\d+\s+"
        r"\d+\s+(?P<nsop>[\d.]+)\s+ns/op"
    )
    data: dict[str, list[float]] = defaultdict(list)
    with open(path) as f:
        for line in f:
            m = pattern.search(line)
            if m:
                data[m.group("name")].append(float(m.group("nsop")))
    return dict(data)


# ── Plot ───────────────────────────────────────────────────────────────

# Display order (classical first, then PQC sorted by expected mean)
DISPLAY_ORDER = [
    "RSA-SHA256",
    "Ed25519",
    "ECDSA-P256",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "MAYO-1",
    "MAYO-3",
    "Falcon-512",
    "SNOVA",
    "Falcon-1024",
    "SLH-DSA-SHA2-128s",
]

# Colour palette: green-to-blue gradient
_CMAP = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])
_PALETTE = [_CMAP(v) for v in np.linspace(0, 1, len(DISPLAY_ORDER))]
COLORS = dict(zip(DISPLAY_ORDER, _PALETTE))


def plot(data: dict[str, list[float]], outfile: str):
    names = [n for n in DISPLAY_ORDER if n in data]
    n_algs = len(names)
    n_samples = min(len(data[n]) for n in names)

    # Convert ns -> us
    means = [np.mean(data[n]) / 1e3 for n in names]
    stds = [np.std(data[n], ddof=1) / 1e3 for n in names]

    plt.rcParams.update({
        "font.family": "Ubuntu",
        "font.size": 11,
        "axes.labelsize": 12,
        "axes.labelweight": "bold",
        "axes.titlesize": 16,
        "axes.titleweight": "bold",
        "axes.titlepad": 20,
    })

    fig, ax = plt.subplots(figsize=(11, 6))

    x = np.arange(n_algs)
    colors = [COLORS.get(n, "#888888") for n in names]

    # Grid behind data
    ax.grid(True, linestyle="--", which="both", color="grey", alpha=0.4)
    ax.set_axisbelow(True)

    # ── Histogram bars with error bars ──────────────────────────────
    bars = ax.bar(
        x, means, width=0.6,
        color=colors, edgecolor="black", linewidth=1.0,
        alpha=1.0, zorder=2,
    )
    ax.errorbar(
        x, means, yerr=stds,
        fmt="none", ecolor="black", elinewidth=1.2, capsize=4, capthick=1.2,
        zorder=3,
    )

    ax.set_yscale("log")
    ax.set_ylabel("Signing time (\u00b5s)")
    ax.set_title(f"DNSSEC signing microbenchmark (n={n_samples})")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=45, ha="right", fontsize=11)

    fig.tight_layout()

    # Save both PDF and PNG
    out = Path(outfile)
    fig.savefig(out, dpi=300, bbox_inches="tight")
    sibling = out.with_suffix(".png" if out.suffix == ".pdf" else ".pdf")
    fig.savefig(sibling, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved plot to {out} + {sibling}")


# ── LaTeX table ────────────────────────────────────────────────────────

def print_latex_table(data: dict[str, list[float]]):
    names = [n for n in DISPLAY_ORDER if n in data]
    print("\n% ── LaTeX table ──")
    print("\\begin{tabular}{l r r r}")
    print("\\toprule")
    print("\\textbf{Algorithm} & $\\bar{s}$ ($\\mu$s) & $\\sigma_s$ ($\\mu$s) & \\textbf{n} \\\\")
    print("\\midrule")
    for n in names:
        vals = np.array(data[n]) / 1e3  # ns -> us
        mean = np.mean(vals)
        std  = np.std(vals, ddof=1)
        cnt  = len(vals)
        if mean >= 1000:
            print(f"{n:22s} & {mean/1e3:8.2f}$\\times 10^3$ & {std/1e3:7.2f}$\\times 10^3$ & {cnt} \\\\")
        else:
            print(f"{n:22s} & {mean:8.2f} & {std:7.2f} & {cnt} \\\\")
    print("\\bottomrule")
    print("\\end{tabular}")


# ── CSV dump for reproducibility ───────────────────────────────────────

def dump_csv(data: dict[str, list[float]], path: str):
    names = [n for n in DISPLAY_ORDER if n in data]
    with open(path, "w") as f:
        f.write("algorithm,run,ns_per_op\n")
        for n in names:
            for i, v in enumerate(data[n]):
                f.write(f"{n},{i},{v}\n")
    print(f"Saved CSV to {path}")


# ── Main ───────────────────────────────────────────────────────────────

def main():
    bench_file = sys.argv[1] if len(sys.argv) > 1 else "bench_results_100.txt"
    out_file   = sys.argv[2] if len(sys.argv) > 2 else "signing_times.pdf"

    if not Path(bench_file).exists():
        print(f"Error: {bench_file} not found", file=sys.stderr)
        sys.exit(1)

    data = parse_bench_file(bench_file)
    if not data:
        print(f"Error: no benchmark data parsed from {bench_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsed {sum(len(v) for v in data.values())} measurements "
          f"across {len(data)} algorithms:")
    for name, vals in sorted(data.items(), key=lambda kv: np.mean(kv[1])):
        arr = np.array(vals) / 1e3
        print(f"  {name:22s}: mean={np.mean(arr):10.2f} us, "
              f"std={np.std(arr, ddof=1):8.2f} us, n={len(vals)}")

    plot(data, out_file)
    dump_csv(data, Path(out_file).with_suffix(".csv"))
    print_latex_table(data)


if __name__ == "__main__":
    main()
