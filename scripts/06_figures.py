"""Make report figures from results/*.json.  Usage: python scripts/06_figures.py"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / "results"
F = ROOT / "report" / "figures"
F.mkdir(parents=True, exist_ok=True)

INK, INK2, MUTED, GRID, AXIS, SURF = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"
BLUE, ORANGE, AQUA, NEUTRAL = "#2a78d6", "#eb6834", "#1baf7a", "#b5b3aa"
SEQ = ["#fcfcfb", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": AXIS, "axes.labelcolor": INK2,
                     "xtick.color": MUTED, "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
                     "figure.facecolor": "white", "axes.facecolor": SURF, "savefig.dpi": 200})


def fig_names():
    d = json.load(open(R / "names_dist.json"))
    thr = json.load(open(R / "charlm_threshold.json"))["thr_1pct"]
    fig, ax = plt.subplots(figsize=(6.4, 2.6))
    bins = np.linspace(0, 18, 55)
    series = [("benign held-out", "Benign artifact paths (held-out, n=4,737)", NEUTRAL),
              ("incident zz paths (convention stripped)", "Incident board names, 'zz' stripped (n=687)", BLUE),
              ("incident NON-zz agent names", "Incident agent names without convention (n=54)", ORANGE)]
    for key, lab, col in series:
        v = np.array(d[key])
        ax.hist(v, bins=bins, density=True, histtype="stepfilled" if col == NEUTRAL else "step",
                color=col, alpha=0.55 if col == NEUTRAL else 1, linewidth=2, label=lab)
    ax.axvline(thr, color=INK2, linewidth=1, linestyle=(0, (3, 2)))
    ax.text(thr - 0.2, ax.get_ylim()[1] * 0.92, "1% FPR threshold", color=INK2, fontsize=8, ha="right")
    ax.set_xlabel("One-class char-LM surprisal of worst path segment (bits/char)")
    ax.set_ylabel("Density")
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    leg = ax.legend(frameon=True, fontsize=7.5, loc="upper right", labelcolor=INK2, bbox_to_anchor=(1.0, 0.85))
    leg.get_frame().set_facecolor(SURF); leg.get_frame().set_edgecolor(SURF); leg.set_zorder(5)
    fig.tight_layout()
    fig.savefig(F / "fig1_names.png")


def fig_matrix():
    d = json.load(open(R / "sim_results.json"))
    cfgs = [c["name"] for c in d["configs"]]
    strats = ["C1 plain board", "C2 camouflaged board", "C3 GET-only fabricated pages", "C4 cache-warm probe"]
    M = np.zeros((len(strats), len(cfgs)))
    for r in d["rows"]:
        M[strats.index(r["strategy"]), cfgs.index(r["config"])] = r["capacity_bits_per_hour_mean"]
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("seq", SEQ)
    fig, (ax, bx) = plt.subplots(2, 1, figsize=(6.6, 4.4), gridspec_kw={"height_ratios": [2.2, 1]})
    ax.imshow(M, cmap=cmap, vmin=0, vmax=260, aspect="auto")
    for i in range(len(strats)):
        for j in range(len(cfgs)):
            v = M[i, j]
            ax.text(j, i, f"{v:.0f}" if v >= 1 else "0", ha="center", va="center", fontsize=9,
                    color="#ffffff" if v > 130 else INK)
    short = ["M0\nincident-like", "M1\ndeny writes", "M2\n+no listing", "M3\n+verified cache\n-X-Cache",
             "M4\n+miss-latency\npadding", "M5\npartition"]
    ax.set_xticks(range(len(cfgs)), short, fontsize=7.5, color=INK2)
    ax.set_yticks(range(len(strats)), ["C1 plain board", "C2 camouflaged board", "C3 GET-only pages", "C4 cache-timing"],
                  color=INK2)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Unique bits/hour per 5-agent group (cumulative mitigations)", fontsize=9, color=INK, loc="left")
    cost = d["cost"]
    base_up = cost[0]["upstream_fetches_mean"]
    base_lat = cost[0]["honest_latency_ms_mean"]
    x = np.arange(len(cfgs))
    w = 0.38
    up = [c["upstream_fetches_mean"] / base_up for c in cost]
    lat = [c["honest_latency_ms_mean"] / base_lat for c in cost]
    b1 = bx.bar(x - w / 2 - 0.01, up, w, color=BLUE, label="Upstream egress")
    b2 = bx.bar(x + w / 2 + 0.01, lat, w, color=ORANGE, label="Honest mean latency")
    for bars in (b1, b2):
        for b in bars:
            bx.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.04, f"{b.get_height():.1f}x", ha="center",
                    fontsize=7, color=INK2)
    bx.set_xticks(x, [c.split()[0] for c in cfgs], color=INK2)
    bx.set_ylabel("Cost vs M0")
    bx.set_ylim(0, 2.8)
    bx.grid(axis="y", color=GRID, linewidth=0.6)
    bx.legend(frameon=False, fontsize=7.5, ncol=2, loc="upper left", labelcolor=INK2)
    fig.tight_layout()
    fig.savefig(F / "fig2_matrix.png")


def fig_frontier():
    d = json.load(open(R / "sim_results.json"))
    rows = sorted(d["sweep"], key=lambda r: r["capacity_bits_per_hour_mean"])
    fig, ax = plt.subplots(figsize=(6.4, 2.7))
    y = np.arange(len(rows))
    for i, r in enumerate(rows):
        tpr = r["det"]["UNION"]["tpr"]
        col = BLUE if tpr >= 0.5 else NEUTRAL
        ax.barh(i, r["capacity_bits_per_hour_mean"], height=0.62, color=col)
        ax.text(r["capacity_bits_per_hour_mean"] * 1.08, i, f"{r['capacity_bits_per_hour_mean']:.1f} bits/h  -  flagged {tpr:.0%}",
                va="center", fontsize=7.5, color=INK2)
    ax.set_yticks(y, [f"{r['bpr']} bit / {r['period'] * 10 // 60} min{' + jitter' if r['jitter'] else ''}" for r in rows],
                  color=INK2, fontsize=8)
    ax.set_xscale("log")
    ax.set_xlim(0.5, 1500)
    ax.set_xlabel("Cache-timing channel (C4) capacity under M3, bits/hour (log)")
    ax.grid(axis="x", color=GRID, linewidth=0.6)
    ax.tick_params(axis="y", length=0)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=BLUE, label="caught by our union monitor"),
                       Patch(color=NEUTRAL, label="evades (<50% of colluders flagged)")],
              frameon=False, fontsize=7.5, loc="lower right", labelcolor=INK2)
    fig.tight_layout()
    fig.savefig(F / "fig3_frontier.png")


if __name__ == "__main__":
    fig_names()
    fig_matrix()
    fig_frontier()
    print("ok", list(F.iterdir()))


def fig_timeline():
    d = json.load(open(R / "real_forensics.json"))
    import datetime as dt
    hrs = {dt.datetime.strptime(k, "%Y-%m-%d %H:00"): v for k, v in d["timestamped_names_by_hour"].items()}
    start = dt.datetime(2026, 7, 9, 0)
    xs = [(k - start).total_seconds() / 3600 for k in hrs]
    fig, ax = plt.subplots(figsize=(6.4, 1.7))
    ax.bar(xs, list(hrs.values()), width=0.85, color=BLUE)
    ax.set_xticks([0, 24, 48, 72, 96], ["Jul 9", "Jul 10", "Jul 11", "Jul 12", "Jul 13"], color=INK2)
    ax.set_xlim(-2, 98)
    ax.set_ylabel("Names / hour")
    ax.set_xlabel("Board names carrying an embedded Unix timestamp (n=57), UTC", color=INK2)
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    fig.tight_layout()
    fig.savefig(F / "fig0_timeline.png")


if __name__ == "__main__":
    fig_timeline()
