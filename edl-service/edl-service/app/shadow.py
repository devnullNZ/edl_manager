from collections.abc import Iterable, Iterator

from .normalize import split_value


def covering_wildcards(host: str) -> Iterator[str]:
    """Wildcard HOSTS that would cover `host`, nearest first, matched on whole-label boundaries.

    a.b.example.com   -> *.b.example.com, *.example.com, *.com
    *.b.example.com   -> *.example.com, *.com      (never itself)
    example.com       -> *.com                      (so example.com / *.example.com both survive)

    `example.com.au` is never covered by `*.example.com`, and neither is `example.com.evil.net`:
    candidates are built from the host's own label suffixes, never by string prefix/suffix tests.
    """
    base = host[2:] if host.startswith("*.") else host
    labels = base.split(".")
    for i in range(1, len(labels)):
        yield "*." + ".".join(labels[i:])


def suppressed_by(targets: Iterable[str], wildcards: Iterable[str]) -> dict[str, str]:
    """Map each target entry to the wildcard entry that suppresses it.

    `wildcards` are the entries allowed to suppress (the caller passes only APPROVED wildcards).
    A wildcard with no path (`*.example.com/`) covers every path on the hosts below it; a wildcard
    with a path covers that same path only. The domain root itself (`example.com/`) is never
    covered by `*.example.com/`. Cost is O(entries x labels): each entry looks up its own label
    suffixes in a set, so 60,000 entries need no pairwise comparison.
    """
    present = set(wildcards)
    out: dict[str, str] = {}
    if not present:
        return out
    for value in targets:
        host, path = split_value(value)
        for wildcard in covering_wildcards(host):
            if wildcard + "/" in present:
                out[value] = wildcard + "/"
                break
            if path and f"{wildcard}/{path}" in present:
                out[value] = f"{wildcard}/{path}"
                break
    return out


def compute_shadows(values: Iterable[str]) -> dict[str, str]:
    """Map each shadowed entry to the entry that shadows it (every wildcard in `values` is a shadower).

    `example.com/` and `*.example.com/` do not shadow each other. Host-only entries are deliberately
    not treated as covering path entries on the same host."""
    values = list(values)
    return suppressed_by(values, (v for v in values if v.startswith("*.")))
