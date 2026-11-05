import re

from .psl import is_public_suffix

_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


MAX_ENTRY_LENGTH = 2048   # Entry.value column size
MAX_SOURCE_LENGTH = 128   # Entry.source column size


class EntryTooLong(ValueError):
    """The normalised entry does not fit the database column. Never truncated."""

    def __init__(self, length: int):
        super().__init__(f"entry is {length} characters after normalisation; the maximum is {MAX_ENTRY_LENGTH}")
        self.length = length


def split_value(value: str) -> tuple[str, str]:
    host, _, path = value.partition("/")
    return host, path


def normalize(raw: str) -> str:
    """Return the canonical entry form: lowercase `host` or `host/path`.

    Strips scheme, credentials, port, query, fragment and trailing slashes.
    Only a leading `*.` wildcard is accepted, and it may not target a public suffix
    (`*.com`, `*.co.uk`, `*.com.au` ...). Raises ValueError if invalid.
    """
    s = raw.strip().lower()
    if not s:
        raise ValueError("empty entry")
    s = _SCHEME.sub("", s)
    s = s.split("#", 1)[0].split("?", 1)[0]
    host, _, path = s.partition("/")
    host = host.rsplit("@", 1)[-1]
    host = re.sub(r":\d+$", "", host).strip(".")
    path = path.strip("/")

    if not host:
        raise ValueError("missing host")
    labels = host.split(".")
    if labels[0] == "*":
        labels = labels[1:]
        if not labels:
            raise ValueError("wildcard needs a domain")
        prefix = "*."
    else:
        prefix = ""
    for label in labels:
        if not _LABEL.match(label):
            raise ValueError(f"invalid hostname label: {label!r}")
    if any(c.isspace() for c in path):
        raise ValueError("whitespace in path")

    base = ".".join(labels)
    if prefix and is_public_suffix(base):
        raise ValueError(f"wildcard '*.{base}' targets a public suffix and would cover unrelated sites; "
                         "use a registrable domain such as *.example." + base)
    host = prefix + base
    value = f"{host}/{path}" if path else host
    if len(value) > MAX_ENTRY_LENGTH:
        raise EntryTooLong(len(value))
    return value
