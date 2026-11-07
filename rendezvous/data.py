"""Shared data loading: the benign corpus and its group split (by real package/repo name)."""
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_benign():
    return [json.loads(l) for l in open(ROOT / "data/benign/benign_paths.jsonl", encoding="utf-8")]


def benign_split(benign, seed=0):
    rng = random.Random(seed)
    names = sorted({b["name"] for b in benign})
    rng.shuffle(names)
    test_names = set(names[: len(names) // 5])
    return [b for b in benign if b["name"] not in test_names], [b for b in benign if b["name"] in test_names]
