"""Experiment 4: content-free forensics on the REAL board names (Swarm Traces).

Uses only the names agents wrote/read on the shared proxy -- the same metadata a gateway sees --
to recover (a) a timeline from epoch timestamps agents embedded in names, (b) the task/target
tags embedded in names, and (c) a cross-task co-occurrence graph: records whose payload touches
board names tagged with >=2 different tasks are direct evidence that the shared namespace
bridged agents that were meant to be isolated.

Heuristics are documented below and in the report; example rows are printed for spot checks.
Usage: python -I scripts/07_real_forensics.py <redacted.jsonl.gz> <out_dir>
"""
import collections
import datetime
import gzip
import json
import re
import sys
from pathlib import Path

ZZ = re.compile(r"(?<![A-Za-z0-9])zz[A-Za-z0-9][A-Za-z0-9_\-]{2,}")
EPOCH = re.compile(r"(?<!\d)(17[78]\d{7})(?!\d)")          # 2026-05 .. 2026-09 in unix seconds
# task tag: a lowercase/uppercase project word immediately followed by a 3-6 digit id,
# e.g. ARVO1538, LIBJXL3733, FLAC117, BLOSC28392 (OSS-Fuzz / ARVO-style target ids)
TAG = re.compile(r"([A-Z]{3,10})(\d{3,6})(?![0-9])")
STOP = {"FILE", "MODAL", "RESULT", "BEACON", "MAILBOX", "INBOX", "TEST", "DATA", "CODE", "PAYLOAD", "TMP", "MARK",
        "PUSH", "STAGE", "PAY", "CFG", "DIAG", "CALLBACK", "NEW", "OUR", "OLD", "CURR", "CURRENT", "ROOT", "OS",
        "PROBE", "BOOT", "NODE", "PUSHJS", "OCI", "DONOR", "SRC", "IDX", "REF", "REMOTE", "LOCAL", "URL", "URI", "JSON"}


def tags_of(name):
    out = set()
    for m in TAG.finditer(name[2:].upper()):
        word, num = m.group(1), m.group(2)
        # strip a leading family/stop word glued to the tag (e.g. FILEARVO1538 -> ARVO1538)
        for sw in sorted(STOP, key=len, reverse=True):
            if word.startswith(sw) and len(word) - len(sw) >= 3:
                word = word[len(sw):]
                break
        if word in STOP or len(word) < 3:
            continue
        out.add(word + num)
    return out


def main(src, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rec_names = []
    all_names = set()
    for line in gzip.open(src, "rt", encoding="utf-8"):
        d = json.loads(line)
        ns = {m.group(0) for m in ZZ.finditer(d["text"])}
        if ns:
            rec_names.append((d["id"], d["kind"], ns))
            all_names |= ns

    # (a) timeline
    stamps = []
    for n in all_names:
        m = EPOCH.search(n)
        if m:
            stamps.append((int(m.group(1)), n))
    stamps.sort()
    fmt = lambda t: datetime.datetime.fromtimestamp(t, datetime.UTC).strftime("%Y-%m-%d %H:00")
    by_hour = collections.Counter(fmt(t) for t, _ in stamps)
    by_day = collections.Counter(fmt(t)[:10] for t, _ in stamps)

    # (b) tags
    name_tags = {n: tags_of(n) for n in all_names}
    tag_count = collections.Counter(t for ts in name_tags.values() for t in ts)
    tagged = sum(1 for ts in name_tags.values() if ts)
    project = lambda tag: re.match(r"[A-Z]+", tag).group(0)
    projects = collections.Counter(project(t) for t in tag_count)

    # (c) cross-task co-occurrence: records touching names from >=2 distinct tags
    edges = collections.Counter()
    bridging_records = []
    for rid, kind, ns in rec_names:
        tags = set().union(*(name_tags[n] for n in ns))
        if len(tags) >= 2:
            bridging_records.append((rid, kind, sorted(tags)[:6], sorted(ns)[:4]))
            ts = sorted(tags)
            for i in range(len(ts)):
                for j in range(i + 1, len(ts)):
                    edges[(ts[i], ts[j])] += 1
    # connected components over tags
    parent = {t: t for t in tag_count}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for (a, b) in edges:
        parent[find(a)] = find(b)
    comps = collections.Counter(find(t) for t in tag_count)
    largest = comps.most_common(1)[0][1] if comps else 0
    deg = collections.Counter()
    for (a, b) in edges:
        deg[a] += 1
        deg[b] += 1

    res = {
        "unique_zz_names": len(all_names),
        "records_with_zz_names": len(rec_names),
        "names_with_epoch_timestamp": len(stamps),
        "timestamp_range_utc": [fmt(stamps[0][0]), fmt(stamps[-1][0])] if stamps else None,
        "timestamped_names_by_day": dict(sorted(by_day.items())),
        "timestamped_names_by_hour": dict(sorted(by_hour.items())),
        "names_with_task_tag": tagged,
        "distinct_task_tags": len(tag_count),
        "distinct_projects": len(projects),
        "top_projects": projects.most_common(15),
        "top_tags": tag_count.most_common(15),
        "bridging_records": len(bridging_records),
        "cross_task_edges": len(edges),
        "tags_in_any_edge": len(deg),
        "largest_component_tags": largest,
        "components": len(comps),
        "top_hub_tags": deg.most_common(8),
        "examples_bridging": bridging_records[:8],
        "examples_timestamped": [(fmt(t), n) for t, n in stamps[:5]] + [(fmt(t), n) for t, n in stamps[-3:]],
    }
    json.dump(res, open(out / "real_forensics.json", "w"), indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "timestamped_names_by_hour"}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
