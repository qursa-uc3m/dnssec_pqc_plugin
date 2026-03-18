#!/usr/bin/env python3
"""Parse Go benchmark output and plot mean signing times with std-dev error bars.

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

# Display order (classical first, then PQC fast-to-slow)
DISPLAY_ORDER = [
    "Ed25519",
    "ECDSA-P256",
    "ML-DSA-44",
    "ML-DSA-65",
    "MAYO-1",
    "Falcon-512",
    "SNOVA",
    "Falcon-1024",
    "SLH-DSA-SHA2-128s",
]

# Colour palette (green to blue gradient)
_CMAP = mcolors.LinearSegmentedColormap.from_list("", ["#9fcf69", "#33acdc"])
_PALETTE = [_CMAP(v) for v in np.linspace(0, 1, len(DISPLAY_ORDER))]
COLORS = dict(zip(DISPLAY_ORDER, _PALETTE))


def plot(data: dict[str, list[float]], outfile: str):
    names = [n for n in DISPLAY_ORDER if n in data]
    means_us = [np.mean(data[n]) / 1e3 for n in names]   # ns -> us
    stds_us  = [np.std(data[n], ddof=1) / 1e3 for n in names]
    colors   = [COLORS.get(n, "#888888") for n in names]

    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 11,
        "axes.labelsize": 12,
        "axes.labelweight": "bold",
    })

    fig, ax = plt.subplots(figsize=(8, 4.5))
    x = np.arange(len(names))
    bars = ax.bar(x, means_us, yerr=stds_us, capsize=4,
                  color=colors, edgecolor="black", linewidth=0.5,
                  error_kw=dict(lw=1.2, capthick=1.2))

    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=30, ha="right", fontsize=10)
    ax.set_ylabel("Signing time (us)")
    ax.set_yscale("log")
    ax.set_title("DNSSEC Signing Microbenchmark (n={})".format(
        min(len(v) for v in data.values())))
    ax.grid(axis="y", alpha=0.3, which="both")

    # Annotate bars with mean value
    for bar, m, s in zip(bars, means_us, stds_us):
        if m > 1000:
            label = f"{m/1e3:.1f} ms"
        else:
            label = f"{m:.1f} us"
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.15,
                label, ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    fig.savefig(outfile, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved plot to {outfile}")


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
