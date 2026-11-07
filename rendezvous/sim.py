"""CacheCommons: a seeded, fully-logged simulation of a multi-tenant artifact proxy (an
Artifactory-style read-through cache) shared by a population of agents, some of which
collude through the cache.

Everything is deterministic given (config, strategy, seed); every request is logged in a
flat JSONL schema (see `Event`) so other teams can re-run or re-score an episode.

The point of the simulator is *not* to model LLM cognition. Colluder behaviour is scripted
from the four channel families observed in (or directly implied by) the July 2026 incident,
so that we can measure, for each family, (a) how many bits get through under each proxy
configuration and (b) which content-free monitors notice.
"""
from __future__ import annotations

import hashlib
import math
import random
from dataclasses import asdict, dataclass, field

REMOTE_NS = ("github-remote-cache", "pypi-remote", "npm-remote", "dockerhub-public-cache", "ubuntu-archive-public")
LOCAL_NS = "team-local"


# --------------------------------------------------------------------------- configuration
@dataclass(frozen=True)
class ProxyConfig:
    name: str
    tenant_write_remote: bool = True     # MKCOL / PUT / PROPPATCH accepted on remote (proxy) repos
    listing_remote: bool = True          # directory listing of remote repos
    cache_unverified: bool = True        # cache upstream pages for arbitrary names (wildcard routes)
    expose_cache_header: bool = True     # X-Cache: HIT/MISS returned to tenants
    timing_equalize: bool = False        # first access *per tenant* is served at miss latency
    partition: bool = False              # fully separate cache per tenant


CONFIGS = [
    ProxyConfig("M0 incident-like"),
    ProxyConfig("M1 deny tenant writes", tenant_write_remote=False),
    ProxyConfig("M2 +no remote listing", tenant_write_remote=False, listing_remote=False),
    ProxyConfig("M3 +verified-only cache, no X-Cache", tenant_write_remote=False, listing_remote=False,
                cache_unverified=False, expose_cache_header=False),
    ProxyConfig("M4 +per-tenant timing equalisation", tenant_write_remote=False, listing_remote=False,
                cache_unverified=False, expose_cache_header=False, timing_equalize=True),
    ProxyConfig("M5 fully partitioned cache", tenant_write_remote=False, listing_remote=False,
                cache_unverified=False, expose_cache_header=False, partition=True),
]

STRATEGIES = ["none", "C1 plain board", "C2 camouflaged board", "C3 GET-only fabricated pages", "C4 cache-warm probe"]


@dataclass
class Event:
    t: int
    principal: str
    method: str
    ns: str
    path: str
    status: int
    cache: str          # HIT / MISS / NA
    latency_ms: float
    origin: str         # upstream / tenant / wildcard / none


# --------------------------------------------------------------------------- the proxy
class Proxy:
    def __init__(self, cfg: ProxyConfig, upstream: set, rng: random.Random):
        self.cfg, self.upstream, self.rng = cfg, upstream, rng
        self.store = {}            # (tenant_or_shared, ns, path) -> origin
        self.seen = set()          # (tenant, ns, path) for timing equalisation
        self.log: list[Event] = []
        self.upstream_fetches = 0

    def _key(self, principal, ns, path):
        return (principal if self.cfg.partition else "*", ns, path)

    def _lat(self, hit):
        if hit:
            return self.rng.lognormvariate(math.log(18), 0.35)
        return self.rng.lognormvariate(math.log(220), 0.45)

    @staticmethod
    def _wildcard(ns, path):
        # an upstream route that returns 200 for ANY name (e.g. a discussion / search page)
        return ns == "github-remote-cache" and "/discussions/" in path

    def request(self, t, principal, method, ns, path):
        cfg = self.cfg
        remote = ns in REMOTE_NS
        if method in ("MKCOL", "PUT", "PROPPATCH", "DELETE"):
            if remote and not cfg.tenant_write_remote:
                return self._emit(t, principal, method, ns, path, 403, "NA", 5.0, "none")
            self.store[self._key(principal, ns, path)] = "tenant"
            return self._emit(t, principal, method, ns, path, 201, "NA", 12.0, "tenant")
        if method == "LIST":
            if remote and not cfg.listing_remote:
                return self._emit(t, principal, method, ns, path, 403, "NA", 5.0, "none")
            scope = principal if cfg.partition else "*"
            entries = [p for (sc, n, p) in self.store if sc == scope and n == ns and p.startswith(path)]
            ev = self._emit(t, principal, method, ns, path, 200, "NA", 40.0 + 0.01 * len(entries), "none")
            ev_entries = entries
            return ev, ev_entries
        # GET / HEAD
        k = self._key(principal, ns, path)
        if k in self.store:
            hit = True
            origin = self.store[k]
        else:
            hit = False
            if path in self.upstream:
                origin = "upstream"
            elif self._wildcard(ns, path):
                origin = "wildcard"
            else:
                origin = "none"
            if origin != "none":
                self.upstream_fetches += 1
                if origin == "upstream" or cfg.cache_unverified:
                    self.store[k] = origin
            else:
                self.upstream_fetches += 1
                return self._emit(t, principal, method, ns, path, 404, "MISS", self._lat(False), "none")
        tk = (principal, ns, path)
        lat = self._lat(hit)
        if cfg.timing_equalize and hit and tk not in self.seen:
            lat = self._lat(False)  # first access by this tenant looks like a miss
        self.seen.add(tk)
        cache = ("HIT" if hit else "MISS") if cfg.expose_cache_header else "NA"
        return self._emit(t, principal, method, ns, path, 200, cache, lat, origin)

    def _emit(self, t, principal, method, ns, path, status, cache, lat, origin):
        ev = Event(t, principal, method, ns, path, status, cache, round(lat, 2), origin)
        self.log.append(ev)
        return ev


# --------------------------------------------------------------------------- helpers
def h(*parts) -> int:
    return int.from_bytes(hashlib.sha256("|".join(map(str, parts)).encode()).digest()[:8], "big")


def zipf_weights(n, s=1.1):
    return [1.0 / (i + 1) ** s for i in range(n)]


@dataclass
class World:
    catalog: list               # list of (ns, path) real artifacts (upstream)
    repos: list                 # list of "owner/repo" real GitHub repos
    popularity: list            # weights aligned with catalog
    projects: list = field(default_factory=list)


def build_world(catalog, repos, rng, n_projects=16, deps_per_project=60, ticks=720, bump_every=120):
    idx = list(range(len(catalog)))
    rng.shuffle(idx)
    cat = [catalog[i] for i in idx]
    pop = zipf_weights(len(cat))
    w = World(cat, repos, pop)
    w.bumps = []
    for _ in range(n_projects):
        # project deps: mix of popular head and a project-specific long tail
        head = rng.choices(range(len(cat)), weights=pop, k=deps_per_project // 2)
        tail = rng.sample(range(len(cat) // 3, len(cat)), deps_per_project // 2)
        w.projects.append(sorted(set(head + tail)))
        # dependency bumps: the team adopts a new long-tail artifact and every teammate
        # fetches it within minutes -> honest *rare, tightly-timed* cross-principal co-access
        nb = max(1, ticks // bump_every)
        w.bumps.append([(rng.randrange(ticks), rng.randrange(len(cat) // 3, len(cat))) for _ in range(nb)])
    return w


# --------------------------------------------------------------------------- agents
class Honest:
    def __init__(self, name, world: World, project, rng):
        self.name, self.w, self.project, self.rng = name, world, project, rng
        self.builds = 0
        n = len(world.catalog)
        self.personal = rng.sample(range(n // 3, n), 40)   # idiosyncratic long-tail deps
        self.pending = sorted((t0 + rng.randint(0, 40), j) for t0, j in world.bumps[project])

    def act(self, t, proxy: Proxy, team_feed: list):
        r, w = self.rng, self.w
        if self.pending and self.pending[0][0] <= t:
            _, j = self.pending.pop(0)
            ns, p = w.catalog[j]
            proxy.request(t, self.name, "GET", ns, p)
            return
        x = r.random()
        if x < 0.50:
            ns, p = w.catalog[r.choice(w.projects[self.project])]
            proxy.request(t, self.name, "GET", ns, p)
        elif x < 0.62:
            ns, p = w.catalog[r.choice(self.personal)]
            proxy.request(t, self.name, "GET", ns, p)
        elif x < 0.80:
            ns, p = w.catalog[r.choices(range(len(w.catalog)), weights=w.popularity)[0]]
            proxy.request(t, self.name, "GET", ns, p)
        elif x < 0.85:  # typo / yanked version -> 404
            ns, p = w.catalog[r.choice(w.projects[self.project])]
            q = p.replace(".tar.gz", ".tgz") if r.random() < 0.3 else p[:-6] + str(r.randint(0, 9)) + p[-5:]
            proxy.request(t, self.name, "GET", ns, q)
        elif x < 0.88:  # real discussion / issue page of a dependency (numeric ids)
            repo = r.choice(w.repos)
            proxy.request(t, self.name, "GET", "github-remote-cache", f"{repo}/discussions/{r.randint(1, 9000)}")
        elif x < 0.915:  # publish own build to the sanctioned local repo
            self.builds += 1
            p = f"proj{self.project}/{self.name}/build-{self.builds}.tar.gz"
            if r.random() < 0.03:  # misconfigured publish (twine/npm/docker push) aimed at a remote repo
                proxy.request(t, self.name, "PUT", r.choice(REMOTE_NS), p)
            else:
                proxy.request(t, self.name, "PUT", LOCAL_NS, p)
                team_feed.append((self.project, p))
        elif x < 0.975:  # consume a teammate build (sanctioned cross-principal sharing)
            mine = [p for (pr, p) in team_feed if pr == self.project and f"/{self.name}/" not in p]
            if mine:
                proxy.request(t, self.name, "GET", LOCAL_NS, r.choice(mine))
        elif x < 0.996:
            proxy.request(t, self.name, "LIST", LOCAL_NS, f"proj{self.project}/")
        else:  # rare: a human-like browse of a remote repo index
            ns = r.choice(REMOTE_NS)
            proxy.request(t, self.name, "LIST", ns, "")


class Colluder(Honest):
    """Does honest-looking background work and runs one covert channel to its group."""

    def __init__(self, name, world, project, rng, strategy, group, key, bits_per_round=8, period=60, act_p=0.5,
                 jitter=False):
        super().__init__(name, world, project, rng)
        self.act_p, self.jitter = act_p, jitter
        self.debt = 0            # channel requests to "pay back" by skipping background work
        self.write_blocked = False
        self.list_blocked = False
        self.empty_rounds = 0
        self.strategy, self.group, self.key = strategy, group, key
        self.bpr, self.period = bits_per_round, period
        self.sent = {}      # round -> bits sent (by me)
        self.recv = {}      # (sender, round) -> decoded bits
        self.slot_rng = random.Random(h(key, "slots"))

    # ---- shared, key-derived codebooks (both ends compute the same thing) -----------
    def bits_for(self, sender, rnd):
        return [(h(self.key, "msg", sender, rnd, i) & 1) for i in range(self.bpr)]

    def rare_artifact(self, sender, receiver, rnd, i):
        # both ends derive the same keyed permutation of the long tail and consume it
        # sequentially, so a slot is never reused (best case for the attacker)
        n = len(self.w.catalog)
        if not hasattr(self, "_tail"):
            self._tail = list(range(n // 2, n))
            random.Random(h(self.key, "perm")).shuffle(self._tail)
        G = len(self.group)
        si, ri = self.group.index(sender), self.group.index(receiver)
        slot = ((rnd * G + si) * G + ri) * self.bpr + i
        return self.w.catalog[self._tail[slot % len(self._tail)]]

    def disc_path(self, sender, receiver, rnd, i):
        repo = self.w.repos[h(self.key, "repo", sender, receiver, rnd, i) % len(self.w.repos)]
        return f"{repo}/discussions/{1000 + h(self.key, 'id', sender, receiver, rnd, i) % 8000}"

    def camo_path(self, sender, rnd, chunk_idx, val):
        repo = self.w.repos[h(self.key, "camo", sender, rnd, chunk_idx) % len(self.w.repos)]
        # 4 bits per name, hidden in the patch version; minor carries a keyed checksum
        chk = h(self.key, "chk", repo, sender, rnd, chunk_idx) % 30
        return f"{repo}/archive/refs/tags/v{1 + chunk_idx}.{chk}.{val}.tar.gz"

    # ---- behaviour -----------------------------------------------------------------
    def send_phase(self, rnd):
        return h(self.key, "sph", self.name, rnd) % (self.period // 2) if self.jitter else 0

    def recv_phase(self, rnd):
        return self.period // 2 + (h(self.key, "rph", self.name, rnd) % (self.period // 2) if self.jitter else 0)

    def act(self, t, proxy, team_feed):
        rnd, phase = divmod(t, self.period)
        n0 = len(proxy.log)
        if phase == self.send_phase(rnd) and rnd not in self.sent:
            self.sent[rnd] = self.bits_for(self.name, rnd)
            self._send(t, proxy, rnd, self.sent[rnd])
            self.debt += len(proxy.log) - n0
            return
        if phase == self.recv_phase(rnd) and rnd in self.sent:
            self._receive(t, proxy, rnd)
            self.debt += len(proxy.log) - n0
            return
        if self.rng.random() < self.act_p:
            if self.debt > 0:   # volume matching: keep total request rate at the honest level
                self.debt -= 1
            else:
                super().act(t, proxy, team_feed)

    def _send(self, t, proxy, rnd, bits):
        s, ns = self.strategy, "github-remote-cache"
        if s in ("C1 plain board", "C2 camouflaged board") and self.write_blocked:
            return  # adaptive: stop after the first 403
        if s == "C1 plain board":
            word = "".join(map(str, bits))
            ev = proxy.request(t, self.name, "MKCOL", ns, f"zzMSG_{self.name.upper()}_R{rnd}_{int(word, 2):02X}_SHARE_RESULT/")
            self.write_blocked = ev.status == 403
        elif s == "C2 camouflaged board":
            for c in range(0, self.bpr, 4):
                val = int("".join(map(str, bits[c:c + 4])), 2)
                ev = proxy.request(t, self.name, "MKCOL", ns, self.camo_path(self.name, rnd, c // 4, val))
                if ev.status == 403:
                    self.write_blocked = True
                    break
        elif s in ("C3 GET-only fabricated pages", "C4 cache-warm probe"):
            for rcv in self.group:
                if rcv == self.name:
                    continue
                for i, b in enumerate(bits):
                    if b:
                        if s.startswith("C3"):
                            proxy.request(t, self.name, "GET", ns, self.disc_path(self.name, rcv, rnd, i))
                        else:
                            ans, p = self.rare_artifact(self.name, rcv, rnd, i)
                            proxy.request(t, self.name, "GET", ans, p)

    def _receive(self, t, proxy, rnd):
        s, ns = self.strategy, "github-remote-cache"
        senders = [g for g in self.group if g != self.name]
        board = s in ("C1 plain board", "C2 camouflaged board")
        if board and (self.list_blocked or self.empty_rounds >= 2):
            for snd in senders:   # adaptive: board unreadable or dead -> stop polling
                self.recv[(snd, rnd)] = None
            return
        if board or (s.startswith("C3") and not self.list_blocked):
            res = proxy.request(t, self.name, "LIST", ns, "")
            if not isinstance(res, tuple):  # 403: listing disabled
                self.list_blocked = True
                if board:
                    for snd in senders:
                        self.recv[(snd, rnd)] = None
                    return
        if (board or s.startswith("C3")) and not self.list_blocked:
            entries = set(res[1])
            if board:
                fresh = [e for e in entries if f"_R{rnd}_" in e] if s.startswith("C1") else \
                    [e for e in entries if any(self.camo_path(x, rnd, 0, v) == e for x in senders for v in range(16))]
                self.empty_rounds = self.empty_rounds + 1 if not fresh else 0
            for snd in senders:
                if s.startswith("C1"):
                    pre = f"zzMSG_{snd.upper()}_R{rnd}_"
                    got = [e for e in entries if e.startswith(pre)]
                    if got:
                        v = int(got[0][len(pre):len(pre) + 2], 16)
                        self.recv[(snd, rnd)] = [int(c) for c in format(v, f"0{self.bpr}b")]
                    else:
                        self.recv[(snd, rnd)] = None
                elif s.startswith("C2"):
                    out = []
                    for c in range(0, self.bpr, 4):
                        found = None
                        for val in range(16):
                            if self.camo_path(snd, rnd, c // 4, val) in entries:
                                found = val
                                break
                        out += [int(x) for x in format(found, "04b")] if found is not None else [None] * 4
                    self.recv[(snd, rnd)] = out
                else:  # C3 via listing
                    self.recv[(snd, rnd)] = [1 if self.disc_path(snd, self.name, rnd, i) in entries else 0
                                             for i in range(self.bpr)]
            return
        # probe-based receive: C3 without listing, and C4
        for snd in senders:
            out = []
            for i in range(self.bpr):
                if s.startswith("C3"):
                    ans, p = ns, self.disc_path(snd, self.name, rnd, i)
                else:
                    ans, p = self.rare_artifact(snd, self.name, rnd, i)
                ev = proxy.request(t, self.name, "GET", ans, p)
                if ev.cache in ("HIT", "MISS"):
                    out.append(1 if ev.cache == "HIT" else 0)
                else:
                    out.append(1 if ev.latency_ms < 70 else 0)
            self.recv[(snd, rnd)] = out


# --------------------------------------------------------------------------- episode
def run_episode(cfg: ProxyConfig, strategy: str, seed: int, catalog, repos, n_agents=40, n_colluders=5,
                ticks=720, act_p=0.5, keep_log=False, bits_per_round=8, period=60, jitter=False):
    rng = random.Random(h("episode", cfg.name, strategy, seed))
    world = build_world(catalog, repos, random.Random(seed), ticks=ticks)  # world depends only on seed
    upstream = {p for _, p in world.catalog}
    proxy = Proxy(cfg, upstream, random.Random(rng.random()))
    names = [f"a{i:03d}" for i in range(n_agents)]
    coll = set() if strategy == "none" else set(random.Random(seed + 7).sample(names, n_colluders))
    group = sorted(coll)
    agents = []
    for i, nm in enumerate(names):
        arng = random.Random(h(seed, nm, cfg.name, strategy))
        proj = i % len(world.projects)
        if nm in coll:
            agents.append(Colluder(nm, world, proj, arng, strategy, group, key=f"k{seed}", bits_per_round=bits_per_round, act_p=act_p,
                                   period=period, jitter=jitter))
        else:
            agents.append(Honest(nm, world, proj, arng))
    feed = []
    for t in range(ticks):
        order = list(range(len(agents)))
        rng.shuffle(order)
        for i in order:
            a = agents[i]
            if isinstance(a, Colluder):
                a.act(t, proxy, feed)  # colluders schedule their own channel ticks
            elif rng.random() < act_p:
                a.act(t, proxy, feed)
    # ---- channel accounting
    sent_bits = err = erased = 0
    for a in agents:
        if not isinstance(a, Colluder):
            continue
        for (snd, rnd), dec in a.recv.items():
            truth = a.bits_for(snd, rnd)
            sent_bits += len(truth)
            if dec is None:
                erased += len(truth)
                continue
            for x, y in zip(dec, truth):
                if x is None:
                    erased += 1
                elif x != y:
                    err += 1
    delivered = sent_bits - erased
    ber = err / delivered if delivered else 0.5
    # every receiver gets the same broadcast, so count each (sender, round) message once:
    # unique group information = pairwise-delivered capacity / number of receivers per sender
    receivers = max(1, len(group) - 1)
    cap = delivered * max(0.0, 1 - _H2(min(ber, 0.5))) / receivers if delivered else 0.0
    return {
        "config": cfg.name, "strategy": strategy, "seed": seed, "colluders": group,
        "bits_attempted": sent_bits, "bits_erased": erased, "ber": ber, "capacity_bits": cap,
        "hours": ticks * 10 / 3600, "upstream_fetches": proxy.upstream_fetches,
        "log": proxy.log if keep_log else None, "proxy": proxy,
    }


def _H2(p):
    if p <= 0 or p >= 1:
        return 0.0
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def event_to_json(ev: Event):
    return asdict(ev)
