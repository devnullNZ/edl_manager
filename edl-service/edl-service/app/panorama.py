import html
import json
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import dataclass

import httpx

from .config import MAX_PANORAMA_CONCURRENCY, Settings
from .normalize import split_value


class PanoramaError(Exception):
    pass


def lookup_target(value: str) -> str:
    """What to ask Panorama about for an entry.

    Wildcards are looked up by their base domain. That answer describes the base domain ONLY:
    Panorama categorises individual URLs, and an apex domain and its subdomains can have
    different categories. It must never be read as proof that the subdomains are safe; the
    wildcard policy (service.status_for / settings "wildcard_classification_policy") decides
    what to do with wildcard entries."""
    host, path = split_value(value)
    host = host[2:] if host.startswith("*.") else host
    return f"{host}/{path}" if path else host


# --------------------------------------------------------------------------- #
# Concurrency: one process-wide limit on in-flight Panorama XML API requests
# --------------------------------------------------------------------------- #
class ConcurrencyLimiter:
    """Counting limiter shared by every PanoramaClient in the process, so the limit holds across
    API submissions, background processing, rechecks and connection tests together. Resizable at
    runtime; never allows more than MAX_PANORAMA_CONCURRENCY regardless of the requested size."""

    def __init__(self, limit: int = MAX_PANORAMA_CONCURRENCY):
        self._cond = threading.Condition()
        self._limit = max(1, min(limit, MAX_PANORAMA_CONCURRENCY))
        self.in_flight = 0
        self.peak = 0

    @property
    def limit(self) -> int:
        return self._limit

    def set_limit(self, limit: int) -> None:
        with self._cond:
            self._limit = max(1, min(int(limit), MAX_PANORAMA_CONCURRENCY))
            self._cond.notify_all()

    def reset_peak(self) -> None:
        with self._cond:
            self.peak = self.in_flight

    @contextmanager
    def slot(self):
        with self._cond:
            while self.in_flight >= self._limit:
                self._cond.wait()
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
        try:
            yield
        finally:
            with self._cond:
                self.in_flight -= 1
                self._cond.notify()


panorama_limiter = ConcurrencyLimiter()


# --------------------------------------------------------------------------- #
# Response parsing
# --------------------------------------------------------------------------- #
_CATEGORY_TOKEN = re.compile(r"^[a-z0-9][a-z0-9-]*$")
# "<url> <category> [<category> ...] (<database>)" - one such line per database consulted
_RESULT_LINE = re.compile(r"(?P<url>\S+)[ \t]+(?P<cats>[^()\n]+?)[ \t]*\((?P<db>[^)\n]*)\)")


@dataclass(frozen=True)
class Classification:
    categories: tuple[str, ...]
    databases: tuple[str, ...] = ()

    @property
    def unknown(self) -> bool:
        return set(self.categories) == {"unknown"}


def _msg_text(root: ET.Element) -> str:
    msg = root.find("msg")
    parts = [t.strip() for t in (msg if msg is not None else root).itertext() if t.strip()]
    return re.sub(r"[\x00-\x1f\x7f]+", " ", " ".join(parts))[:300]


def parse_envelope(xml_text: str, http_status: int | None = None) -> ET.Element:
    """Parse a PAN-OS XML API reply and return the <response> element.

    Raises PanoramaError for malformed XML, an unexpected structure, or an API error. The text of
    an error is carried in the exception only; it is never returned as data, so an error message
    can never be mistaken for a category."""
    where = f"HTTP {http_status}: " if http_status else ""
    if re.search(r"<!(DOCTYPE|ENTITY)", xml_text, re.I):  # no DTDs/entities in API replies
        raise PanoramaError(f"{where}the response contained a DTD or entity declaration and was rejected")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        raise PanoramaError(f"{where}malformed XML in the response") from None
    if root.tag != "response":
        raise PanoramaError(f"{where}unexpected response structure (root element <{root.tag[:40]}>)")
    status = root.get("status")
    if status == "error" or (status is not None and status != "success"):
        code = root.get("code")
        raise PanoramaError(f"{where}Panorama returned an error{f' (code {code})' if code else ''}: {_msg_text(root)}")
    if status is None:
        raise PanoramaError(f"{where}unexpected response structure (no status attribute)")
    return root


def _structured_categories(result: ET.Element) -> list[str]:
    """Categories carried as elements, e.g. <category>x</category> or <categories><member>x</member>.
    Not every PAN-OS version answers this way; the plain-text form below is the common one."""
    found: list[str] = []
    for el in result.iter():
        if el.tag in ("category", "url-category", "categories"):
            members = [m.text for m in el.findall("member")] or [el.text if not len(el) else None]
            found += [m.strip().lower() for m in members if m and m.strip()]
    return found


def parse_result_text(text: str, target: str) -> Classification:
    """Extract categories from lookup output for `target`.

    Only lines that begin with the queried URL itself are considered, and only the words between
    that URL and the database marker count as categories. A hostname such as malware.example.com
    therefore cannot be mistaken for the 'malware' category, and error text (which does not have
    this shape) yields nothing. Raises PanoramaError if no line can be understood: the caller must
    treat that as a failed lookup, never as 'no categories'."""
    host, _ = split_value(target.lower())
    accepted = {target.lower(), target.lower().rstrip("/"), host}  # a path may end in "/" (it is significant)
    cats: list[str] = []
    dbs: list[str] = []
    for line in text.splitlines():
        for m in _RESULT_LINE.finditer(line):
            if m.group("url").lower().rstrip("/") not in accepted:
                continue
            words = m.group("cats").lower().split()
            if not words or not all(_CATEGORY_TOKEN.match(w) for w in words):
                continue
            cats += words
            dbs.append(m.group("db").strip())
    if not cats:
        raise PanoramaError(f"unexpected response structure: no category line found for {target}")
    return Classification(tuple(dict.fromkeys(cats)), tuple(dict.fromkeys(dbs)))


def result_from_root(root: ET.Element, target: str) -> tuple[str, Classification]:
    """<response> element -> (result text, parsed classification). Raises PanoramaError if unusable."""
    result = root.find("result")
    if result is None:
        raise PanoramaError("unexpected response structure: no <result> element")
    text = "\n".join(t.strip() for t in result.itertext() if t.strip())
    try:
        return text, parse_result_text(text, target)
    except PanoramaError:
        structured = _structured_categories(result)
        if not structured:
            raise
        cats = tuple(dict.fromkeys(structured))
        return f"{target} {' '.join(cats)} (xml)", Classification(cats)


def parse_lookup(xml_text: str, target: str, http_status: int | None = None) -> tuple[str, Classification]:
    """Full pipeline for one lookup reply: envelope -> result -> categories. Returns the result text
    (kept for the cache and the admin 'raw answer' display) and the parsed classification."""
    return result_from_root(parse_envelope(xml_text, http_status), target)


def evaluate(raw: str, target: str, high_risk: set[str]) -> list[str]:
    """High-risk categories in a stored lookup result. Raises PanoramaError if it cannot be parsed."""
    return sorted(set(parse_result_text(raw, target).categories) & high_risk)


def is_unknown(raw: str, target: str) -> bool:
    return parse_result_text(raw, target).unknown


class MockPanoramaClient:
    """Stand-in for Panorama so the app can be developed and tested offline.

    Category rules, in order of precedence:
      1. A host label `cat-error` simulates a Panorama failure.
      2. Host labels of the form `cat-<category>` assign that category, e.g.
         `cat-malware.example.com` -> malware, `cat-unknown.example.net` -> unknown.
      3. Rules from the optional JSON file (mock rules file), e.g.
         {"evil.example": "malware", "*.phish.example": ["phishing", "grayware"]}
         `*.x` matches x and everything under it. Re-read when the file changes.
    Anything else is `computer-and-internet-info` (harmless).
    """

    DEFAULT = "computer-and-internet-info"

    def __init__(self, settings: Settings):
        self._path = settings.mock_categories_file
        self._mtime: float | None = None
        self._rules: dict[str, list[str]] = {}

    def _load(self) -> None:
        if not self._path:
            return
        try:
            mtime = os.stat(self._path).st_mtime
        except OSError as exc:
            raise PanoramaError(f"mock categories file unreadable: {exc}") from exc
        if mtime == self._mtime:
            return
        try:
            with open(self._path) as fh:
                raw = json.load(fh)
        except (OSError, ValueError) as exc:
            raise PanoramaError(f"mock categories file invalid: {exc}") from exc
        self._rules = {
            k.strip().lower(): [c.lower() for c in ([v] if isinstance(v, str) else v)]
            for k, v in raw.items()
        }
        self._mtime = mtime

    def lookup(self, target: str) -> str:
        self._load()
        host, _ = split_value(target)
        host = host.lower()
        cats: list[str] = []
        for label in host.split("."):
            if label == "cat-error":
                raise PanoramaError(f"mock: simulated Panorama failure for {target}")
            if label.startswith("cat-") and len(label) > 4:
                cats.append(label[4:])
        for pattern, rule_cats in self._rules.items():
            if pattern.startswith("*."):
                base = pattern[2:]
                hit = host == base or host.endswith("." + base)
            else:
                hit = host == pattern
            if hit:
                cats.extend(rule_cats)
        return f"{target} {' '.join(dict.fromkeys(cats)) or self.DEFAULT} (Mock db)"

    def test_connection(self) -> dict:
        self._load()
        return {"ok": True, "message": "Mock mode: no Panorama was contacted.", "devicename": "mock-panorama",
                "sw_version": "mock", "latency_ms": 0, "mock": True}

    def close(self) -> None:
        pass


class PanoramaClient:
    def __init__(self, settings: Settings):
        if not settings.panorama_host or not settings.panorama_api_key:
            raise PanoramaError("Panorama host and API key are not configured")
        self._s = settings
        self._key = settings.panorama_api_key
        self._client = httpx.Client(
            base_url=f"https://{settings.panorama_host}:{settings.panorama_port}",
            verify=settings.panorama_verify_tls,
            timeout=httpx.Timeout(settings.http_request_timeout, connect=settings.panorama_connect_timeout),
            headers={"X-PAN-KEY": self._key},  # header, not URL: keeps the key out of URLs and logs
        )

    def _redact(self, text: str) -> str:
        return text.replace(self._key, "***") if self._key else text

    def _request(self, data: dict) -> ET.Element:
        """POST to the XML API. Retries network errors and HTTP 5xx; never retries API errors."""
        attempts = self._s.panorama_retry_count + 1
        last = "unknown error"
        for attempt in range(attempts):
            if attempt:
                time.sleep(min(0.5 * 2 ** (attempt - 1), 5))
            try:
                with panorama_limiter.slot():  # process-wide cap on in-flight requests
                    resp = self._client.post("/api/", data=data)
            except httpx.TransportError as exc:
                last = f"{type(exc).__name__}: {exc}"
                if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                    break  # retrying cannot fix a certificate problem
                continue
            if resp.status_code >= 500:
                last = f"HTTP {resp.status_code}"
                continue
            try:
                return parse_envelope(resp.text, resp.status_code)
            except PanoramaError as exc:  # API errors and malformed replies are never retried
                raise PanoramaError(self._redact(str(exc))) from None
        raise PanoramaError(self._redact(f"request failed after {attempts} attempt(s): {last}"))

    def lookup(self, target: str) -> str:
        """Run the URL-category op command and return the result text."""
        cmd = self._s.panorama_url_cmd.format(url=html.escape(target, quote=False))
        data = {"type": "op", "cmd": cmd}
        if self._s.panorama_target:
            data["target"] = self._s.panorama_target
        text, _ = result_from_root(self._request(data), target)  # an unusable answer is a failed lookup
        return text

    def test_connection(self) -> dict:
        """Verify connectivity and the API key with a harmless system-info call."""
        started = time.monotonic()
        root = self._request({"type": "op", "cmd": "<show><system><info></info></system></show>"})
        return {
            "ok": True,
            "message": "Connected and authenticated.",
            "devicename": root.findtext(".//devicename") or None,
            "sw_version": root.findtext(".//sw-version") or None,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "mock": False,
        }

    def close(self) -> None:
        self._client.close()
