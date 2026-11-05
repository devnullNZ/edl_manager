from collections.abc import Iterable, Iterator

from .normalize import split_value


def covering_wildcards(host: str) -> Iterator[str]:
    """Wildcards that would cover `host`, nearest first.

    a.b.example.com   -> *.b.example.com, *.example.com, *.com
    *.b.example.com   -> *.example.com, *.com      (never itself)
    example.com       -> *.com                      (so example.com / *.example.com both survive)
    """
    base = host[2:] if host.startswith("*.") else host
    labels = base.split(".")
    for i in range(1, len(labels)):
        yield "*." + ".".join(labels[i:])


def compute_shadows(values: Iterable[str]) -> dict[str, str]:
    """Map each shadowed entry to the entry that shadows it.

    An entry is shadowed when a wildcard that covers its host exists with no path
    (covers every path) or with the identical path. `example.com` and
    `*.example.com` do not shadow each other. Host-only entries are deliberately
    not treated as covering path entries on the same host.
    """
    present = set(values)
    shadowed: dict[str, str] = {}
    for value in present:
        host, path = split_value(value)
        for wildcard in covering_wildcards(host):
            if wildcard in present:
                shadowed[value] = wildcard
                break
            if path and f"{wildcard}/{path}" in present:
                shadowed[value] = f"{wildcard}/{path}"
                break
    return shadowed
