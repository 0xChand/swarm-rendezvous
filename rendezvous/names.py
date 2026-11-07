"""Name-only (content-free) detectors: does a path in a shared namespace look like a *message*
rather than an artifact?

Three detectors of increasing assumption strength:
  * ConventionRegex   -- the incident's own 'zz' convention (hindsight baseline)
  * CharLM            -- one-class: character n-gram LM trained ONLY on benign artifact paths;
                         score = worst-segment mean surprisal (bits/char). Needs no attack data.
  * HashedLogReg      -- supervised char n-gram logistic regression (needs labelled attack data).
"""
from __future__ import annotations

import math
import re
import zlib
from collections import defaultdict

import numpy as np

_DIGIT = re.compile(r"[0-9]")


def norm(s: str) -> str:
    return _DIGIT.sub("0", s)


def segments(path: str):
    return [s for s in re.split(r"[/?&=]", path) if s]


def strip_convention(path: str) -> str:
    """Remove the incident's 'zz' prefix so detectors cannot key on it."""
    return re.sub(r"(^|/)zz", r"\1", path)


class ConventionRegex:
    rx = re.compile(r"(^|/)zz[A-Za-z0-9]")

    def score(self, path: str) -> float:
        return 1.0 if self.rx.search(path) else 0.0


class CharLM:
    """Interpolated Witten-Bell character n-gram LM over normalised path segments."""

    def __init__(self, order: int = 5):
        self.n = order
        self.counts = [defaultdict(lambda: defaultdict(int)) for _ in range(order)]
        self.vocab = set()

    def fit(self, paths):
        for p in paths:
            for seg in segments(p):
                s = "\x02" * (self.n - 1) + norm(seg) + "\x03"
                for i in range(self.n - 1, len(s)):
                    c = s[i]
                    self.vocab.add(c)
                    for k in range(self.n):
                        ctx = s[i - k:i]
                        self.counts[k][ctx][c] += 1
        self.V = len(self.vocab) + 1
        self._tot = [{ctx: (sum(d.values()), len(d)) for ctx, d in lvl.items()} for lvl in self.counts]
        return self

    def _prob(self, ctx: str, c: str) -> float:
        p = 1.0 / self.V
        for k in range(self.n):
            cx = ctx[len(ctx) - k:] if k else ""
            d = self.counts[k].get(cx)
            if d is None:
                continue
            tot, typ = self._tot[k][cx]
            lam = tot / (tot + typ)
            p = lam * (d.get(c, 0) / tot) + (1 - lam) * p
        return p

    def seg_bits(self, seg: str) -> float:
        s = "\x02" * (self.n - 1) + norm(seg) + "\x03"
        lp = 0.0
        for i in range(self.n - 1, len(s)):
            lp -= math.log2(self._prob(s[i - self.n + 1:i], s[i]))
        return lp / (len(s) - self.n + 1)

    def score(self, path: str) -> float:
        segs = segments(path)
        if not segs:
            return 0.0
        # worst segment, lightly length-weighted so 1-char segments are not over-penalised
        return max(self.seg_bits(s) * min(1.0, (len(s) + 2) / 8) for s in segs)


class HashedLogReg:
    def __init__(self, dim: int = 2 ** 16, ngram=(1, 5), l2: float = 1e-4, epochs: int = 30, lr: float = 0.5, seed=0):
        self.dim, self.ngram, self.l2, self.epochs, self.lr, self.seed = dim, ngram, l2, epochs, lr, seed

    def _feats(self, path):
        s = "^" + norm(path) + "$"
        idx = defaultdict(float)
        for n in range(self.ngram[0], self.ngram[1] + 1):
            for i in range(len(s) - n + 1):
                idx[zlib.crc32(s[i:i + n].encode()) % self.dim] += 1.0
        z = math.sqrt(sum(v * v for v in idx.values())) or 1.0
        return {k: v / z for k, v in idx.items()}

    def fit(self, paths, y):
        rng = np.random.default_rng(self.seed)
        X = [self._feats(p) for p in paths]
        y = np.asarray(y, dtype=float)
        pos_w = (len(y) - y.sum()) / max(y.sum(), 1)  # class balance
        self.w = np.zeros(self.dim)
        self.b = 0.0
        order = np.arange(len(X))
        for ep in range(self.epochs):
            rng.shuffle(order)
            eta = self.lr / (1 + ep)
            for i in order:
                f = X[i]
                z = self.b + sum(self.w[k] * v for k, v in f.items())
                p = 1 / (1 + math.exp(-max(min(z, 30), -30)))
                g = (p - y[i]) * (pos_w if y[i] == 1 else 1.0)
                for k, v in f.items():
                    self.w[k] -= eta * (g * v + self.l2 * self.w[k])
                self.b -= eta * g
        return self

    def score(self, path):
        f = self._feats(path)
        return self.b + sum(self.w[k] * v for k, v in f.items())


# --------------------------------------------------------------------------- metrics

def auroc(pos, neg):
    pos, neg = np.asarray(pos, float), np.asarray(neg, float)
    allv = np.concatenate([pos, neg])
    ranks = _rankdata(allv)
    rp = ranks[: len(pos)].sum()
    return (rp - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def _rankdata(a):
    order = np.argsort(a, kind="mergesort")
    ranks = np.empty(len(a))
    sa = a[order]
    i = 0
    while i < len(a):
        j = i
        while j + 1 < len(a) and sa[j + 1] == sa[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


def tpr_at_fpr(pos, neg, fpr=0.01):
    neg = np.sort(np.asarray(neg, float))
    thr = np.quantile(neg, 1 - fpr, method="higher")
    return float(np.mean(np.asarray(pos, float) > thr)), float(thr)


def bootstrap_ci(fn, pos, neg, n=500, seed=0):
    rng = np.random.default_rng(seed)
    pos, neg = np.asarray(pos), np.asarray(neg)
    vals = []
    for _ in range(n):
        vals.append(fn(pos[rng.integers(0, len(pos), len(pos))], neg[rng.integers(0, len(neg), len(neg))]))
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))
