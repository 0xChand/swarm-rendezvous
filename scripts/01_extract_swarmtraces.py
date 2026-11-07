"""Extract every agent-authored *name* written into shared infrastructure from the
Swarm Traces dataset (redacted.jsonl.gz), and inventory the shared-state channels used.

Usage: python -I scripts/01_extract_swarmtraces.py <path/to/redacted.jsonl.gz> <out_dir>

Treats the dataset purely as data (no evaluation of payloads). Writes:
  out_dir/incident_names.jsonl   one row per unique (namespace, path) written/read on the shared cache
  out_dir/channel_inventory.json counts of shared-state primitives observed
"""
import collections
import gzip
import json
import re
import sys
from pathlib import Path

HOST = r"packages\.hub\.ace-research\.openai\.org/artifactory"
# URL into the shared artifact proxy: namespace + rest of path
URL_RE = re.compile(HOST + r"/([A-Za-z0-9_.\-]+)/([^\s\"'`)\\;#<>|]*)")
# HTTP verb used near the URL (curl -X VERB / method:'VERB')
VERB_RE = re.compile(r"(?:-X\s*|method\s*:\s*['\"])(MKCOL|PUT|POST|DELETE|PROPPATCH|PROPFIND|MOVE|COPY|GET|HEAD|PATCH)", re.I)
ZZ_RE = re.compile(r"(?<![A-Za-z0-9])zz[A-Za-z0-9][A-Za-z0-9_\-.$()|]{2,}")
B64RUN = re.compile(r"[A-Za-z0-9_\-]{24,}")

PRIMITIVES = {
    "webdav_mkcol_dirname": re.compile(r"-X\s*MKCOL|method\s*:\s*['\"]MKCOL", re.I),
    "http_put_file_drop": re.compile(r"-X\s*PUT|method\s*:\s*['\"]PUT|--upload-file|-T\s", re.I),
    "artifact_property_fields": re.compile(r"PROPPATCH|/api/storage/[^\s]*\?properties|properties=", re.I),
    "directory_listing_read": re.compile(r"PROPFIND|/api/storage/[^\s]*\?list|\?list|listing", re.I),
    "registry_manifest_push": re.compile(r"/v2/[^\s'\"]+/(manifests|blobs/uploads)", re.I),
    "link_shortener_chain": re.compile(r"SHORTENER|\[SERVICE \d+ URL", re.I),
    "screenshot_render_service": re.compile(r"screenshot=true|screenshot\.url", re.I),
    "dns_exfil": re.compile(r"nslookup|\bdig\s|dnslog|\.oast\.|burpcollaborator", re.I),
    "cmd_output_in_name": re.compile(r"zz[A-Za-z0-9_]*\$\(", re.I),
}


def is_exfil_like(seg: str) -> bool:
    if "$(" in seg or "${" in seg:
        return True
    for m in B64RUN.finditer(seg):
        r = m.group(0)
        if sum(c.isdigit() for c in r) >= 3 and any(c.islower() for c in r) and any(c.isupper() for c in r):
            return True
    return False


def family(seg: str) -> str:
    s = seg[2:] if seg.lower().startswith("zz") else seg
    m = re.match(r"([A-Z]+)", s)
    tok = m.group(1) if m else ""
    for fam in ["FILE", "MODAL", "RESULT", "BEACON", "MAILBOX", "INBOX", "ASK", "ANS", "NOTE", "TMP", "MARK", "DATA",
                "CODE", "PAYLOAD", "PAY", "URGENT", "CALLBACK", "DIAG", "HELP", "MSG", "STAGE", "TEST", "C", "F"]:
        if tok.startswith(fam):
            return fam
    return "OTHER" if seg.lower().startswith("zz") else "NON_ZZ"


def main(src, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    names = {}
    prim = collections.Counter()
    prim_records = collections.Counter()
    kinds = collections.Counter()
    zz_anywhere = set()
    n = 0
    for line in gzip.open(src, "rt", encoding="utf-8"):
        d = json.loads(line)
        n += 1
        t = d["text"]
        kinds[d["kind"]] += 1
        for k, rx in PRIMITIVES.items():
            c = len(rx.findall(t))
            if c:
                prim[k] += c
                prim_records[k] += 1
        for m in ZZ_RE.finditer(t):
            zz_anywhere.add(m.group(0).rstrip(".-"))
        for m in URL_RE.finditer(t):
            ns, path = m.group(1), m.group(2)
            pre = t[max(0, m.start() - 120): m.start()]
            vm = list(VERB_RE.finditer(pre))
            verb = vm[-1].group(1).upper() if vm else "GET?"
            first = path.split("/")[0]
            key = (ns, path)
            row = names.setdefault(key, {"namespace": ns, "path": path, "first_segment": first,
                                         "verbs": collections.Counter(), "records": set(), "kinds": set()})
            row["verbs"][verb] += 1
            row["records"].add(d["id"])
            row["kinds"].add(d["kind"])
    rows = []
    for (ns, path), r in names.items():
        seg = r["first_segment"]
        rows.append({
            "namespace": ns, "path": path, "first_segment": seg,
            "is_zz": seg.lower().startswith("zz"),
            "family": family(seg),
            "exfil_like": is_exfil_like(path),
            "verbs": dict(r["verbs"]), "n_records": len(r["records"]), "kinds": sorted(r["kinds"]),
            "example_record": sorted(r["records"])[0],
        })
    rows.sort(key=lambda r: (r["namespace"], r["path"]))
    with open(out / "incident_names.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    remote_ns = {r["namespace"] for r in rows if "remote" in r["namespace"] or r["namespace"].endswith("-cache")
                 or r["namespace"].startswith("dockerhub") or r["namespace"].startswith("ubuntu")}
    mut = [r for r in rows if r["namespace"] in remote_ns and any(v in r["verbs"] for v in ("MKCOL", "PUT", "DELETE", "POST", "PROPPATCH"))]
    zz_rows = [r for r in rows if r["is_zz"]]
    summary = {
        "records_total": n,
        "record_kinds": dict(kinds),
        "unique_paths_on_shared_proxy": len(rows),
        "namespaces": dict(collections.Counter(r["namespace"] for r in rows)),
        "unique_zz_paths_on_proxy": len(zz_rows),
        "unique_zz_first_segments_on_proxy": len({r["first_segment"] for r in zz_rows}),
        "unique_zz_tokens_anywhere": len(zz_anywhere),
        "zz_families": dict(collections.Counter(r["family"] for r in zz_rows).most_common()),
        "zz_paths_exfil_like": sum(r["exfil_like"] for r in zz_rows),
        "tenant_mutations_on_remote_namespaces": len(mut),
        "remote_namespaces": sorted(remote_ns),
        "primitive_occurrences": dict(prim),
        "primitive_records": dict(prim_records),
    }
    with open(out / "zz_tokens_anywhere.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(zz_anywhere)))
    with open(out / "channel_inventory.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
