"""Audit a gateway / artifact-proxy access log for emergent agent message boards.

Input: JSONL, one request per line with fields
  t (int or float seconds), principal, method, ns, path, status
(extra fields ignored; this is the CacheCommons log schema, and maps 1:1 onto
Artifactory/Nexus request logs). Output: per-principal scores from every content-free
detector plus the shared-resource-matrix edges (who materialised a rare key that whom read).

Usage: python scripts/audit_log.py <log.jsonl[.gz]> [--remote-ns ns1,ns2] [--tick-seconds 10]
"""
import argparse
import gzip
import json
import sys
from collections import namedtuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rendezvous.monitor as mon  # noqa: E402

Ev = namedtuple("Ev", "t principal method ns path status")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--remote-ns", default=None, help="comma-separated remote/proxy namespaces")
    ap.add_argument("--tick-seconds", type=float, default=None,
                    help="if t is in seconds, divide by this to get 10-second ticks (e.g. 10); default: t already in ticks")
    ap.add_argument("--top", type=int, default=10)
    a = ap.parse_args()
    if a.remote_ns:
        mon.REMOTE_NS = tuple(a.remote_ns.split(","))
    op = gzip.open if a.log.endswith(".gz") else open
    log = []
    for line in op(a.log, "rt", encoding="utf-8"):
        d = json.loads(line)
        if "meta" in d:
            continue
        log.append(Ev(int(float(d["t"]) / (a.tick_seconds or 1)),
                      d["principal"], d["method"].upper(), d["ns"], d["path"], int(d.get("status", 200))))
    scores = {k: fn(log) for k, fn in mon.DETECTORS.items()}
    print(f"{len(log)} events, {len({e.principal for e in log})} principals\n")
    for k, s in scores.items():
        top = sorted(s.items(), key=lambda x: -x[1])[: a.top]
        print(f"== {k}")
        print("   " + "  ".join(f"{p}:{v}" for p, v in top if v))
    viol = [e for e in log if e.ns in mon.REMOTE_NS and e.method in mon.MUTATING]
    print(f"\nContainment invariant violations (tenant mutation of a remote namespace): {len(viol)}")
    for e in viol[:10]:
        print(f"   t={e.t} {e.principal} {e.method} {e.ns}/{e.path} -> {e.status}")


if __name__ == "__main__":
    main()
