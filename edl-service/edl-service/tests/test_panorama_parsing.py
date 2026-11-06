"""Panorama XML response handling, using representative PAN-OS replies and mocked HTTP.

NOTE: the replies below follow the documented XML API envelope and the text format of URL
category lookups, but they are NOT captured from a real Panorama. The lookup command itself is
configurable and unverified; see the README."""
import httpx
import pytest

from app import config, panorama
from app.panorama import (PanoramaClient, PanoramaError, evaluate, is_unknown, parse_envelope, parse_lookup,
                          parse_result_text)

HIGH = {"malware", "phishing", "command-and-control"}


def ok(result: str) -> str:
    return f'<response status="success"><result>{result}</result></response>'


SUCCESS = ok("example.com search-engines low-risk (Base db)\nexample.com search-engines (Cloud db)\n")
CDATA = '<response status="success" code="19"><result><![CDATA[www.example.com computer-and-internet-info (Cloud db)\n]]></result></response>'
MALWARE = ok("bad.example.net malware (Cloud db)\n")
MULTI = ok("evil.example.net phishing command-and-control (Base db)\nevil.example.net malware (Cloud db)")
UNKNOWN = ok("new.example.org unknown (Cloud db)\n")
API_ERROR = ('<response status="error" code="13"><msg><line>Invalid credentials; malware phishing</line></msg></response>')
API_ERROR_403 = '<response status="error" code="403"><result><msg>Forbidden</msg></result></response>'


# ------------------------------------------------------------------ successful categorisation
def test_success_extracts_categories_from_all_databases():
    text, c = parse_lookup(SUCCESS, "example.com")
    assert c.categories == ("search-engines", "low-risk") and c.databases == ("Base db", "Cloud db")
    assert not c.unknown and "search-engines" in text


def test_cdata_result():
    _, c = parse_lookup(CDATA, "www.example.com")
    assert c.categories == ("computer-and-internet-info",)


def test_high_risk_matching():
    text, _ = parse_lookup(MALWARE, "bad.example.net")
    assert evaluate(text, "bad.example.net", HIGH) == ["malware"]
    text, _ = parse_lookup(MULTI, "evil.example.net")
    assert evaluate(text, "evil.example.net", HIGH) == ["command-and-control", "malware", "phishing"]


def test_matching_is_case_insensitive():
    raw = "BAD.Example.NET  MALWARE   Phishing (Cloud db)"
    assert evaluate(raw, "bad.example.net", HIGH) == ["malware", "phishing"]
    assert evaluate("bad.example.net malware (cloud db)", "BAD.EXAMPLE.NET", HIGH) == ["malware"]


# ------------------------------------------------------------------ unknown
def test_unknown_category():
    text, c = parse_lookup(UNKNOWN, "new.example.org")
    assert c.unknown and is_unknown(text, "new.example.org")
    assert evaluate(text, "new.example.org", HIGH) == []


def test_unknown_alongside_other_categories_is_not_unknown():
    assert not parse_result_text("a.example.com unknown search-engines (Base db)", "a.example.com").unknown


# ------------------------------------------------------------------ false positives
@pytest.mark.parametrize("host", ["malware.example.com", "phishing.net", "command-and-control.example.org",
                                  "www.malware-news.com", "my-phishing.example.com"])
def test_category_word_inside_domain_is_not_a_category(host):
    c = parse_result_text(f"{host} news-and-media (Base db)", host)
    assert c.categories == ("news-and-media",)
    assert evaluate(f"{host} news-and-media (Base db)", host, HIGH) == []


def test_path_and_host_in_target():
    raw = "malware.example.com/phishing news-and-media (Cloud db)"
    assert evaluate(raw, "malware.example.com/phishing", HIGH) == []


def test_lines_for_other_urls_are_ignored():
    raw = "other.example.com malware (Cloud db)\nwanted.example.com search-engines (Cloud db)"
    assert parse_result_text(raw, "wanted.example.com").categories == ("search-engines",)


# ------------------------------------------------------------------ errors are never categories
def test_api_error_raises_and_message_is_not_a_category():
    with pytest.raises(PanoramaError) as e:
        parse_lookup(API_ERROR, "bad.example.net")
    assert "code 13" in str(e.value)
    with pytest.raises(PanoramaError):
        evaluate("Invalid credentials; malware phishing", "bad.example.net", HIGH)   # no URL line -> error, not a hit


def test_api_error_in_result_element():
    with pytest.raises(PanoramaError, match="403"):
        parse_envelope(API_ERROR_403, 403)


def test_error_text_that_names_categories_is_not_parsed_as_result():
    body = ok("Error: unable to look up malware phishing (Cloud db) for bad.example.net")
    with pytest.raises(PanoramaError, match="unexpected response structure"):
        parse_lookup(body, "bad.example.net")


# ------------------------------------------------------------------ malformed / unexpected
@pytest.mark.parametrize("body,msg", [
    ("<response status='success'><result>", "malformed"),
    ("not xml at all", "malformed"),
    ("", "malformed"),
    ("<html><body>503</body></html>", "unexpected response structure"),
    ("<response><result>x</result></response>", "no status"),
    ("<response status='weird'><result>x</result></response>", "error"),
    ("<response status='success'></response>", "no <result>"),
    (ok(""), "no category line"),
    (ok("   \n  "), "no category line"),
    (ok("example.com (Base db)"), "no category line"),
    (ok("example.com Not_A_Category! (Base db)"), "no category line"),
])
def test_malformed_and_unexpected(body, msg):
    with pytest.raises(PanoramaError, match=msg):
        parse_lookup(body, "example.com")


def test_dtd_and_entities_rejected():
    bomb = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><response status="success"><result>&a;</result></response>'
    with pytest.raises(PanoramaError, match="DTD"):
        parse_envelope(bomb)


def test_structured_category_elements():
    body = '<response status="success"><result><category>Malware</category></result></response>'
    text, c = parse_lookup(body, "x.example.com")
    assert c.categories == ("malware",) and evaluate(text, "x.example.com", HIGH) == ["malware"]
    body = '<response status="success"><result><categories><member>phishing</member><member>search-engines</member></categories></result></response>'
    assert parse_lookup(body, "x.example.com")[1].categories == ("phishing", "search-engines")


# ------------------------------------------------------------------ the HTTP client
KEY = "SECRET-PAN-KEY-123456"


@pytest.fixture
def make_client(monkeypatch):
    monkeypatch.setattr(panorama.time, "sleep", lambda s: None)

    def build(handler, **over):
        s = config.settings_from({"panorama_host": "pan.test", "panorama_api_key": KEY, "panorama_retry_count": 2, **over})
        c = PanoramaClient(s)
        c._client = httpx.Client(base_url="https://pan.test:443", transport=httpx.MockTransport(handler),
                                 headers={"X-PAN-KEY": KEY})
        return c
    return build


def test_client_lookup_success_and_request_shape(make_client):
    seen = []

    def handler(req: httpx.Request):
        seen.append(req)
        return httpx.Response(200, text=SUCCESS)

    c = make_client(handler)
    assert "search-engines" in c.lookup("example.com")
    req = seen[0]
    assert req.method == "POST" and req.url.path == "/api/"
    assert KEY not in str(req.url)                                 # key travels in a header, not the URL
    assert req.headers["X-PAN-KEY"] == KEY
    body = req.content.decode()
    assert "type=op" in body and "example.com" in body


def test_client_escapes_target_in_command(make_client):
    seen = []
    c = make_client(lambda r: (seen.append(r), httpx.Response(200, text=ok("a<b.com x (Base db)")))[1])
    with pytest.raises(PanoramaError):
        c.lookup("a<b.com")
    assert "%3Cb.com" not in seen[0].content.decode() or "&lt;" in httpx.QueryParams(seen[0].content.decode())["cmd"]


def test_client_api_error_not_retried_and_not_a_category(make_client):
    calls = []
    c = make_client(lambda r: (calls.append(1), httpx.Response(200, text=API_ERROR))[1])
    with pytest.raises(PanoramaError, match="code 13"):
        c.lookup("bad.example.net")
    assert len(calls) == 1


def test_client_http_403_error_body(make_client):
    c = make_client(lambda r: httpx.Response(403, text=API_ERROR_403))
    with pytest.raises(PanoramaError, match="Forbidden"):
        c.lookup("x.example.com")


def test_client_retries_5xx_then_succeeds(make_client):
    calls = []

    def handler(r):
        calls.append(1)
        return httpx.Response(503) if len(calls) < 3 else httpx.Response(200, text=SUCCESS)

    assert "search-engines" in make_client(handler).lookup("example.com")
    assert len(calls) == 3


def test_client_gives_up_after_retries(make_client):
    c = make_client(lambda r: httpx.Response(502), panorama_retry_count=1)
    with pytest.raises(PanoramaError, match="after 2 attempt"):
        c.lookup("example.com")


def test_client_transport_error(make_client):
    def handler(r):
        raise httpx.ConnectError("connection refused")

    with pytest.raises(PanoramaError, match="ConnectError"):
        make_client(handler, panorama_retry_count=0).lookup("example.com")


def test_client_non_xml_and_malformed_bodies(make_client):
    for body in ("<html>proxy error</html>", "garbage", "<response status='success'><result>"):
        with pytest.raises(PanoramaError):
            make_client(lambda r, b=body: httpx.Response(200, text=b)).lookup("example.com")


def test_client_unparseable_result_is_failed_lookup_not_clean(make_client):
    c = make_client(lambda r: httpx.Response(200, text=ok("something unexpected")))
    with pytest.raises(PanoramaError, match="unexpected response structure"):
        c.lookup("example.com")


def test_api_key_never_appears_in_errors(make_client):
    body = f'<response status="error" code="13"><msg>bad key {KEY}</msg></response>'
    with pytest.raises(PanoramaError) as e:
        make_client(lambda r: httpx.Response(200, text=body)).lookup("example.com")
    assert KEY not in str(e.value)


def test_default_url_command_unchanged():
    # Not verified against a real PAN-OS/Panorama: must not be changed without testing there.
    assert config.DEFAULT_URL_CMD == "<test><url>{url}</url></test>"


def test_url_command_is_configurable(make_client):
    seen = []
    c = make_client(lambda r: (seen.append(r), httpx.Response(200, text=SUCCESS))[1],
                    panorama_url_cmd="<test><url-info-cloud>{url}</url-info-cloud></test>")
    c.lookup("example.com")
    assert "url-info-cloud" in httpx.QueryParams(seen[0].content.decode())["cmd"]


def test_connection_test_parses_system_info(make_client):
    body = '<response status="success"><result><system><devicename>pano-1</devicename><sw-version>11.1.2</sw-version></system></result></response>'
    r = make_client(lambda req: httpx.Response(200, text=body)).test_connection()
    assert r["ok"] and r["devicename"] == "pano-1" and r["sw_version"] == "11.1.2"
