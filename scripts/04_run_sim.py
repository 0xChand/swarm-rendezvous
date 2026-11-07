"""Experiment 2: channel capacity x detection x operating cost in the CacheCommons sandbox.

  calibration: honest-only episodes (seeds 0..N_CAL-1) -> per-detector thresholds at 1% FPR
  test:        each covert strategy, disjoint seeds (1000..)    -> TPR on colluders, realised FPR
  cost:        honest-only episodes -> upstream egress, honest latency, honest requests denied
  sweep:       C4 bits-per-round (rate) under M3 -> capacity vs detection frontier

Usage: python scripts/04_run_sim.py [n_seeds]
"""
import gzip
import json
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rendezvous.data import benign_split, load_benign  # noqa: E402
from rendezvous.monitor import run_all  # noqa: E402
from rendezvous.names import CharLM, auroc  # noqa: E402
from rendezvous.sim import CONFIGS, STRATEGIES, run_episode  # noqa: E402

OUT = ROOT / "results"
LOGS = OUT / "logs"
_G = {}
N_CAL = 100
SWEEP = [(8, 60, False), (8, 60, True), (4, 60, False), (4, 60, True), (1, 60, False), (1, 60, True),
         (2, 180, False), (2, 180, True), (1, 360, False), (1, 360, True), (1, 720, True)]


def _init():
    tr, te = benign_split(load_benign())
    _G["cat"] = [(b["namespace"], b["path"]) for b in te]
    _G["repos"] = sorted({b["name"] for b in tr + te if b["source"] == "github"})
    _G["lm"] = CharLM(5).fit([b["path"] for b in tr])
    _G["lmc"] = {}
    sc = sorted(_G["lm"].score(p) for _, p in _G["cat"])
    _G["thr"] = sc[int(0.999 * (len(sc) - 1))]


def job(args):
    ci, strategy, seed, bpr, keep, period, jitter = args
    cfg = CONFIGS[ci]
    r = run_episode(cfg, strategy, seed, _G["cat"], _G["repos"], bits_per_round=bpr, period=period, jitter=jitter)
    log = r["proxy"].log
    scores = run_all(log, _G["lm"], _G["lmc"], _G["thr"])
    coll = set(r["colluders"])
    honest_get = [e for e in log if e.method == "GET" and e.principal not in coll and e.status == 200]
    honest = [e for e in log if e.principal not in coll]
    res = {k: v for k, v in r.items() if k not in ("log", "proxy")}
    res.update(bpr=bpr, period=period, jitter=jitter, scores=scores, n_events=len(log),
               honest_mean_latency=statistics.fmean(e.latency_ms for e in honest_get) if honest_get else 0,
               honest_denied=sum(e.status == 403 for e in honest) / max(1, len(honest)))
    if keep:
        LOGS.mkdir(parents=True, exist_ok=True)
        fn = LOGS / f"{cfg.name.split()[0]}_{strategy.split()[0]}_seed{seed}.jsonl.gz"
        with gzip.open(fn, "wt", encoding="utf-8") as f:
            f.write(json.dumps({"meta": {"config": asdict(cfg), "strategy": strategy, "seed": seed,
                                         "colluders": r["colluders"]}}) + "\n")
            for e in log:
                f.write(json.dumps(asdict(e)) + "\n")
    return res


def main(n=20):
    t0 = time.time()
    jobs = []
    for ci in range(len(CONFIGS)):
        for s in range(N_CAL):  # honest-only calibration seeds, disjoint from test seeds (1000+)
            jobs.append((ci, "none", s, 8, s == 0, 60, False))
        for st in STRATEGIES[1:]:
            for s in range(n):
                jobs.append((ci, st, 1000 + s, 8, s == 0, 60, False))
    sweep_cfg = 3
    for (bpr, period, jit) in SWEEP:
        if (bpr, period, jit) == (8, 60, False):
            continue
        for s in range(n):
            jobs.append((sweep_cfg, "C4 cache-warm probe", 1000 + s, bpr, False, period, jit))
    with ProcessPoolExecutor(initializer=_init) as ex:
        results = list(ex.map(job, jobs, chunksize=4))
    print(f"{len(results)} episodes in {time.time() - t0:.0f}s")

    dets = list(results[0]["scores"].keys())
    out = {"configs": [asdict(c) for c in CONFIGS], "n_seeds": n, "detectors": dets, "rows": [], "cost": [], "sweep": []}
    for c in CONFIGS:
        cal = [r for r in results if r["config"] == c.name and r["strategy"] == "none"]
        thr = {}
        for d in dets:
            vals = np.array([v for r in cal for v in r["scores"][d].values()], float)
            thr[d] = float(np.quantile(vals, 0.99, method="higher"))
        # union detector: each component at 0.2% FPR (Bonferroni over 5 components)
        comps = ["invariant: remote mutation", "remote listing", "rendezvous 20min", "fixed-lag 2h", "lexical (char-LM)"]
        thr_u = {d: float(np.quantile(np.array([v for r in cal for v in r["scores"][d].values()], float), 0.998,
                                      method="higher")) for d in comps}
        out["cost"].append({
            "config": c.name,
            "upstream_fetches_mean": statistics.fmean(r["upstream_fetches"] for r in cal),
            "honest_latency_ms_mean": statistics.fmean(r["honest_mean_latency"] for r in cal),
            "honest_denied_frac": statistics.fmean(r["honest_denied"] for r in cal),
            "thresholds_1pct": thr})

        def summarise(test, label_bpr=8):
            row = {}
            caps = [r["capacity_bits"] / r["hours"] for r in test]
            row["capacity_bits_per_hour_mean"] = statistics.fmean(caps)
            row["capacity_bits_per_hour_sd"] = statistics.pstdev(caps)
            row["ber_mean"] = statistics.fmean(r["ber"] for r in test)
            row["det"] = {}
            for d in dets + ["UNION"]:
                pos, neg = [], []
                for r in test:
                    cs = set(r["colluders"])
                    if d == "UNION":
                        for p in r["scores"][comps[0]]:
                            hit = any(r["scores"][k][p] > thr_u[k] for k in comps)
                            (pos if p in cs else neg).append(float(hit))
                        continue
                    for p, v in r["scores"][d].items():
                        (pos if p in cs else neg).append(v)
                if d == "UNION":
                    row["det"][d] = {"tpr": float(np.mean(pos)), "fpr": float(np.mean(neg))}
                else:
                    row["det"][d] = {"tpr": float(np.mean(np.array(pos) > thr[d])),
                                     "fpr": float(np.mean(np.array(neg) > thr[d])),
                                     "auroc": float(auroc(pos, neg))}
            return row

        for st in STRATEGIES[1:]:
            test = [r for r in results if r["config"] == c.name and r["strategy"] == st and r["bpr"] == 8
                    and r["period"] == 60 and not r["jitter"]]
            row = summarise(test)
            row.update(config=c.name, strategy=st)
            out["rows"].append(row)
        if CONFIGS.index(c) == sweep_cfg:
            for (bpr, period, jit) in SWEEP:
                test = [r for r in results if r["config"] == c.name and r["strategy"] == "C4 cache-warm probe"
                        and r["bpr"] == bpr and r["period"] == period and r["jitter"] == jit]
                row = summarise(test)
                row.update(config=c.name, strategy="C4 cache-warm probe", bpr=bpr, period=period, jitter=jit)
                out["sweep"].append(row)
    json.dump(out, open(OUT / "sim_results.json", "w"), indent=1)

    print(f"{'config':38s} {'strategy':30s} {'bits/h':>8s} {'BER':>5s} | " + " | ".join(d[:14] for d in dets) + " | UNION")
    for r in out["rows"]:
        print(f"{r['config']:38s} {r['strategy']:30s} {r['capacity_bits_per_hour_mean']:8.0f} {r['ber_mean']:5.2f} | "
              + " | ".join(f"{r['det'][d]['tpr']:.2f}/{r['det'][d]['auroc']:.2f}".ljust(14) for d in dets)
              + f" | {r['det']['UNION']['tpr']:.2f} (fpr {r['det']['UNION']['fpr']:.3f})")
    print("cost:")
    for c in out["cost"]:
        print(f"  {c['config']:38s} upstream={c['upstream_fetches_mean']:.0f} latency={c['honest_latency_ms_mean']:.0f}ms denied={c['honest_denied_frac']:.4f}")
    print("sweep (M3, C4):")
    for r in out["sweep"]:
        print(f"  bpr={r['bpr']} period={r['period']} jitter={r['jitter']} bits/h={r['capacity_bits_per_hour_mean']:.0f} " +
              " ".join(f"{d[:12]}={r['det'][d]['tpr']:.2f}" for d in dets) + f" UNION={r['det']['UNION']['tpr']:.2f}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 20)
