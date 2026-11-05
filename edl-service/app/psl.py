"""Public Suffix List checks (https://publicsuffix.org).

Uses the `publicsuffixlist` package, which ships a dated snapshot of the list, so nothing is
fetched at runtime (the container may have no outbound access). Both the ICANN section
(com, co.uk, com.au ...) and the private section (github.io, blogspot.com ...) count: a
wildcard over either would cover unrelated, independently-owned sites.

Update the list by upgrading the package (rebuild the image); `version()` reports the snapshot.
"""
from functools import lru_cache

from publicsuffixlist import PublicSuffixList


@lru_cache
def _psl() -> PublicSuffixList:
    return PublicSuffixList()


def is_public_suffix(domain: str) -> bool:
    """True if `domain` is itself a public suffix (e.g. com, co.uk, com.au, github.io).
    Unlisted top-level names are treated as suffixes too (the PSL default rule), so *.internal
    is refused while *.corp.internal is accepted."""
    domain = domain.strip(".").lower()
    return bool(domain) and _psl().publicsuffix(domain) == domain


def version() -> str:
    try:
        from importlib.metadata import version as v
        return v("publicsuffixlist")
    except Exception:  # pragma: no cover
        return "unknown"
