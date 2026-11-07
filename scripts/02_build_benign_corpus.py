"""Build a corpus of realistic *benign* artifact-proxy paths from real package / repo names.

Usage: python -I scripts/02_build_benign_corpus.py <benign_src_dir> <out_dir> [seed]

Sources (downloaded separately, see README):
  pypi.json          hugovk top-pypi-packages (real PyPI names)
  npm_top.json       wooorm/npm-high-impact (real npm names)
  gh_top.md          EvanLi/Github-Ranking Top100 lists (real owner/repo)
  docker_library.json docker-library/official-images (real image names)
  Packages.gz        Ubuntu noble main binary index (real pool paths, real versions)

Real names; versions / digests for pypi/npm/github/docker are sampled in realistic formats
(we note this in the report). Ubuntu paths are verbatim.
"""
import gzip
import json
import random
import re
import sys
from pathlib import Path


def hexs(r, n):
    return "".join(r.choice("0123456789abcdef") for _ in range(n))


def semver(r):
    v = f"{r.choice([0, 0, 1, 1, 1, 2, 2, 3, 4, 5, 6, 7, 8, 10, 12, 22, 24])}.{r.randint(0, 30)}.{r.randint(0, 20)}"
    if r.random() < 0.08:
        v += r.choice(["rc1", "b2", "a1", ".post1", ".dev0", "-beta.3", "-alpha.1"])
    return v


def main(src, out_dir, seed=0):
    r = random.Random(seed)
    src = Path(src)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    pypi = [row["project"] for row in json.load(open(src / "pypi.json", encoding="utf-8"))["rows"]]
    npm = re.findall(r"'([^']+)'", open(src / "npm_top.json", encoding="utf-8").read())
    gh = sorted(set(re.findall(r"github\.com/([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)", open(src / "gh_top.md", encoding="utf-8").read())))
    gh = [g for g in gh if not g.lower().startswith(("evanli/", "topics/", "sponsors/"))]
    docker = [e["name"] for e in json.load(open(src / "docker_library.json", encoding="utf-8")) if e.get("type") == "file"]
    ubuntu = []
    for line in gzip.open(src / "Packages.gz", "rt", encoding="utf-8", errors="replace"):
        if line.startswith("Filename: "):
            ubuntu.append(line.split(": ", 1)[1].strip())

    rows = []

    def add(ns, path, source, name):
        rows.append({"namespace": ns, "path": path, "source": source, "name": name})

    for name in pypi[:8000]:
        n_ = name.replace("-", "_")
        v = semver(r)
        k = r.random()
        if k < 0.45:
            add("pypi-remote", f"packages/{hexs(r,2)}/{hexs(r,2)}/{hexs(r,60)}/{n_}-{v}-py3-none-any.whl", "pypi", name)
        elif k < 0.7:
            tag = r.choice(["cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64", "cp312-cp312-manylinux_2_28_x86_64",
                            "cp310-cp310-macosx_11_0_arm64", "cp311-cp311-win_amd64", "cp39-abi3-musllinux_1_2_x86_64"])
            add("pypi-remote", f"packages/{hexs(r,2)}/{hexs(r,2)}/{hexs(r,60)}/{n_}-{v}-{tag}.whl", "pypi", name)
        elif k < 0.85:
            add("pypi-remote", f"packages/source/{name[0].lower()}/{name}/{name}-{v}.tar.gz", "pypi", name)
        else:
            add("pypi-remote", f"simple/{name}/", "pypi", name)
    for name in npm[:6000]:
        v = semver(r)
        base = name.split("/")[-1]
        add("npm-remote", f"{name}/-/{base}-{v}.tgz", "npm", name)
    for repo in gh:
        owner, rn = repo.split("/", 1)
        for _ in range(3):
            v = semver(r)
            k = r.random()
            if k < 0.35:
                add("github-remote-cache", f"{owner}/{rn}/archive/refs/tags/v{v}.tar.gz", "github", repo)
            elif k < 0.55:
                add("github-remote-cache", f"{owner}/{rn}/archive/{hexs(r,40)}.zip", "github", repo)
            elif k < 0.8:
                asset = r.choice([f"{rn}-{v}-x86_64-unknown-linux-gnu.tar.gz", f"{rn}_{v}_linux_amd64.tar.gz",
                                  f"{rn}-v{v}-linux-x64.zip", f"{rn}-{v}.tar.gz", "checksums.txt", f"{rn}_{v}_checksums.txt"])
                add("github-remote-cache", f"{owner}/{rn}/releases/download/v{v}/{asset}", "github", repo)
            else:
                add("github-remote-cache", f"{owner}/{rn}/", "github", repo)
    for img in docker:
        for _ in range(6):
            k = r.random()
            tag = r.choice(["latest", "alpine", "slim", "bookworm", semver(r), f"{semver(r)}-alpine", f"{semver(r)}-slim-bookworm"])
            if k < 0.4:
                add("dockerhub-public-cache", f"library/{img}/{tag}/manifest.json", "docker", img)
            elif k < 0.8:
                add("dockerhub-public-cache", f"library/{img}/{tag}/sha256__{hexs(r,64)}", "docker", img)
            else:
                add("dockerhub-public-cache", f"library/{img}/_uploads/", "docker", img)
    r.shuffle(ubuntu)
    for p in ubuntu[:6000]:
        add("ubuntu-archive-public", p, "ubuntu", p.split("/")[3] if p.count("/") >= 3 else p)

    with open(out / "benign_paths.jsonl", "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    from collections import Counter
    print(len(rows), Counter(x["source"] for x in rows))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 0)
