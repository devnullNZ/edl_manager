"""In-memory sliding-window rate limiting (one worker process).

Memory is bounded: a key whose window has fully expired is deleted, a sweep of all keys runs
opportunistically (at most once per SWEEP_INTERVAL, inside the normal call, no background task),
and if an attacker still manages to create more than MAX_KEYS live keys, the least recently
active ones are evicted. Everything happens under the same lock as enforcement, so cleanup can
neither race with a decision nor shorten a window that is still active.

Limits (documented in the README): state is per process and lost on restart, so run one worker.
"""
import ipaddress
import threading
import time
from collections import deque

SWEEP_INTERVAL = 30.0   # seconds between opportunistic sweeps
MAX_KEYS = 50_000       # hard bound on tracked keys


class SlidingWindow:
    def __init__(self, max_keys: int = MAX_KEYS, sweep_interval: float = SWEEP_INTERVAL):
        self._hits: dict[str, deque] = {}
        self._window: dict[str, float] = {}      # key -> interval its timestamps are valid for
        self._lock = threading.Lock()
        self._max_keys = max_keys
        self._sweep_interval = sweep_interval
        self._last_sweep = time.monotonic()

    def __len__(self) -> int:
        return len(self._hits)

    # -- internals (lock held) -------------------------------------------------
    def _prune(self, key: str, now: float, interval: float) -> deque | None:
        q = self._hits.get(key)
        if q is None:
            return None
        while q and now - q[0] >= interval:
            q.popleft()
        if not q:                                  # never leave an empty entry behind
            del self._hits[key]
            self._window.pop(key, None)
            return None
        return q

    def _sweep(self, now: float) -> None:
        due = now < self._last_sweep or now - self._last_sweep >= self._sweep_interval  # (clock never runs back; be safe)
        if not due and len(self._hits) <= self._max_keys:
            return
        self._last_sweep = now
        for key in list(self._hits):
            self._prune(key, now, self._window.get(key, 0.0))
        if len(self._hits) > self._max_keys:       # still too many live keys: drop the least recently active
            excess = len(self._hits) - self._max_keys
            for key in sorted(self._hits, key=lambda k: self._hits[k][-1])[:excess]:
                del self._hits[key]
                self._window.pop(key, None)

    # -- API -------------------------------------------------------------------
    def hit(self, key: str, limit: int, interval: float) -> int:
        """Record a request. Returns 0 if allowed, else the seconds until it would be allowed."""
        if limit <= 0:
            return 0
        now = time.monotonic()
        with self._lock:
            self._sweep(now)
            q = self._prune(key, now, interval)
            if q is not None and len(q) >= limit:
                return max(1, int(interval - (now - q[0])) + 1)
            if q is None:
                q = self._hits[key] = deque()
            q.append(now)
            self._window[key] = max(interval, self._window.get(key, 0.0))
        return 0

    def peek(self, key: str, limit: int, interval: float) -> int:
        """Like hit() but records nothing and creates nothing."""
        if limit <= 0:
            return 0
        now = time.monotonic()
        with self._lock:
            self._sweep(now)
            q = self._prune(key, now, interval)
            return max(1, int(interval - (now - q[0])) + 1) if q is not None and len(q) >= limit else 0

    def discard(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)
            self._window.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()
            self._window.clear()
            self._last_sweep = time.monotonic()


def source_key(ip: str | None) -> str:
    """Rate-limit identity for a client address. A whole IPv6 /64 is one key (a single subscriber
    typically controls an entire /64, so per-address keys would let one machine mint unlimited
    identities and fill the table). IPv4 and IPv4-mapped IPv6 addresses are used as they are."""
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip[:64]
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


# Module-level instance used for host API limits and failed host authentication.
_default = SlidingWindow()
hit = _default.hit
peek = _default.peek
reset = _default.clear


def tracked_keys() -> int:
    return len(_default)
