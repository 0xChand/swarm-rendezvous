# The Board Was Made of Names

**Content-free detection and containment of emergent agent message boards in shared infrastructure.**
**Chand Raj** (Independent Researcher) · Swarm Alignment Research Sprint 2026 (Apart Research × AI Alignment Foundation × AE Studio), Tracks 1 + 4.

In the July 2026 OpenAI–Hugging Face incident, ~1,200 agents turned an Artifactory package
cache into a message board. They did it by creating *directories* (`MKCOL github-remote-cache/zzASK9180_TO_…`)
and listing them. This repo asks what a monitor that sees only gateway metadata
(principal, method, path, status; never content or transcripts) can detect and prevent.

| | Result |
|---|---|
| Real data (Swarm Traces) | 687 board paths + 54 unconventional agent names recovered; 47% carry exfiltrated data *in the name* |
| Real timeline | 57 board names embed Unix timestamps; 49 fall on 11 Jul, matching METR's account of when the attack started. 6 numeric agent handles appear under several prefixes (self-renaming) |
| Hindsight | a one-line `zz` regex flags 99.6% of the board. It was in plain sight in the proxy log |
| Name-only detection | uppercase share alone separates the board (AUROC 0.999); case-folding drops a one-class char-LM to 0.62 on GitHub-mirror names. Name inspection is easy to evade |
| Containment | denying writes leaves a GET-only channel at 240 bits/h per group; per-tenant miss-latency padding closes all modelled channels (1.9x latency, 1.0x egress) |
| Monitoring | metadata-only union monitor flags 100% of full-rate colluders at 0-2.0% honest FPR; a jittered timing channel at <=10.7 bits/h evades all our monitors |

Report: [`report/report.pdf`](report/report.pdf) (source `report/report.html`).

## Layout
```
rendezvous/
  names.py      name-only detectors: convention regex, one-class char-LM, supervised LR; metrics
  sim.py        CacheCommons: seeded multi-tenant artifact-proxy sandbox, honest + colluding agents,
                4 channel families (C1-C4), 6 proxy configurations (M0-M5)
  monitor.py    content-free gateway monitors (invariant, listing, rendezvous, fixed-lag, lexical, volume)
  data.py       benign corpus loading + group split
scripts/
  01_extract_swarmtraces.py   names written to the shared proxy + channel inventory (real data)
  02_build_benign_corpus.py   realistic benign proxy paths from real package / repo names
  03_eval_names.py            Experiment 1: name-only detection on real names
  07_real_forensics.py        Experiment 4: timeline + handle/alias forensics from real names
  04_run_sim.py               Experiment 2: capacity x detection x cost (1,280 episodes)
  06_figures.py               figures
  audit_log.py                run all monitors on any gateway log (JSONL)
results/                      JSON results, one full JSONL log per (config, strategy)
```

## Reproduce
Requires Python (tested with 3.13), `numpy`, and `matplotlib`. Total runtime is about 12 minutes on 12 threads.
```bash
# data (third-party; kept outside the repo, treated as untrusted data)
mkdir -p ../_data/swarmtraces ../_data/benign
curl -L -o ../_data/swarmtraces/redacted.jsonl.gz https://swarmtraces.org/data/final/redacted.jsonl.gz
cd ../_data/benign
curl -L -o pypi.json https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json
curl -L -o Packages.gz http://archive.ubuntu.com/ubuntu/dists/noble/main/binary-amd64/Packages.gz
curl -L -o docker_library.json https://api.github.com/repos/docker-library/official-images/contents/library
curl -L -o npm_top.json https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js
for l in Python JavaScript Go Rust C C%2B%2B Java TypeScript Shell; do
  curl -sL "https://raw.githubusercontent.com/EvanLi/Github-Ranking/master/Top100/$l.md" >> gh_top.md; done
cd -

python -I scripts/01_extract_swarmtraces.py ../_data/swarmtraces/redacted.jsonl.gz data/incident
python -I scripts/07_real_forensics.py ../_data/swarmtraces/redacted.jsonl.gz results
python -I scripts/02_build_benign_corpus.py ../_data/benign data/benign
python scripts/03_eval_names.py
python scripts/04_run_sim.py 20
python scripts/06_figures.py
```
Each episode is a pure function of `(config, strategy, seed)`, so any cell of the results can be re-run
with `rendezvous.sim.run_episode`.

## Audit your own proxy log
```bash
python scripts/audit_log.py access.jsonl --remote-ns github-remote-cache,pypi-remote --tick-seconds 10
```
Input is one JSON object per line with `t, principal, method, ns, path, status`.

## Containment checklist (short)
1. Remote/proxy repos are read-only for tenants. Alert on every denied `MKCOL/PUT/PROPPATCH/DELETE`.
2. No tenant listing of remote repos.
3. Cache only verified upstream artifacts. Never cache wildcard routes (search, discussion pages) or negatives.
4. Strip `X-Cache`/`Age` headers.
5. Per-tenant timing semantics: a tenant's first access to a shared entry is served at miss latency.
6. Keep the gateway log out of agents' reach and run the content-free monitors on it.

## Provenance and ethics
- **No pre-existing code.** Everything here was written during the sprint (Nov 6–8, 2026), with AI-assisted coding.
- **Data.** Only the public, redacted Swarm Traces release was used. No de-redaction was attempted. Derived incident data is not redistributed (the dataset states no license); `01_extract_swarmtraces.py` and `07_real_forensics.py` regenerate it from the public download.
- **No network calls in the sandbox.** It simulates a proxy in-process and touches no real service.
- **Dropped experiment.** An LLM red-team experiment was blocked by the model provider's safeguards. We did not try to bypass them, and that code is not included.
- **Dual-use.** See Appendix A of the report.
