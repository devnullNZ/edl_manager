import json
import os

os.environ.setdefault("API_KEY", "k")

import pytest

from app import service
from app.config import Settings
from app.panorama import MockPanoramaClient, PanoramaError, evaluate

BLOCKED = {"malware", "phishing", "command-and-control"}


def mock(tmp_path=None, rules=None):
    path = ""
    if rules is not None:
        p = tmp_path / "rules.json"
        p.write_text(json.dumps(rules))
        path = str(p)
    return MockPanoramaClient(Settings(panorama_mode="mock", mock_categories_file=path))


def hits(client, target):
    return evaluate(client.lookup(target), target, BLOCKED)


def test_default_is_harmless():
    assert hits(mock(), "example.com") == []


def test_cat_label_convention():
    c = mock()
    assert hits(c, "cat-malware.example.com") == ["malware"]
    assert hits(c, "www.cat-command-and-control.example.net/x") == ["command-and-control"]


def test_cat_error_simulates_failure():
    with pytest.raises(PanoramaError):
        mock().lookup("cat-error.example.com")


def test_rules_file_exact_and_wildcard(tmp_path):
    c = mock(tmp_path, {"evil.example": "malware", "*.phish.example": ["phishing"]})
    assert hits(c, "evil.example") == ["malware"]
    assert hits(c, "www.evil.example") == []          # exact rule only
    assert hits(c, "phish.example") == ["phishing"]   # wildcard covers apex and below
    assert hits(c, "a.b.phish.example") == ["phishing"]
    assert hits(c, "fine.example") == []


def test_rules_file_hot_reload(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text('{"x.example": "malware"}')
    c = MockPanoramaClient(Settings(panorama_mode="mock", mock_categories_file=str(p)))
    assert hits(c, "x.example") == ["malware"]
    p.write_text("{}")
    os.utime(p, (p.stat().st_atime, p.stat().st_mtime + 5))
    assert hits(c, "x.example") == []


def test_bad_rules_file_is_a_lookup_error(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text("not json")
    c = MockPanoramaClient(Settings(panorama_mode="mock", mock_categories_file=str(p)))
    with pytest.raises(PanoramaError):
        c.lookup("x.example")


def test_get_client_selects_mock(monkeypatch):
    monkeypatch.setattr(service, "_client", None)
    monkeypatch.setattr(service, "get_settings", lambda: Settings(panorama_mode="mock"))
    assert isinstance(service.get_client(), MockPanoramaClient)
