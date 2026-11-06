"""Documentation promises for v2.2.0, and sync behaviours the README describes."""
from pathlib import Path

from conftest import apex_policy, feed, sync

README = Path(__file__).resolve().parent.parent.joinpath("README.md").read_text()


def test_readme_documents_the_release_and_the_apex_limitation():
    assert README.startswith("# EDL Publisher — release 2.2.0")
    for needle in ("## Source sync", "POST /v1/lists/{name}/sync", "## Wildcard suppression", "## URL normalisation",
                   "## Stored entries versus the effective published EDL", "## Release notes 2.2.0",
                   "## Upgrading from v2.1.1", "Classify Apex Domain", "dry_run", "delete_missing", "confirm_empty",
                   "does **not**\nprove that every subdomain is safe", "explicit policy decision", "Rollback",
                   "max_sync_size", "sync_classification_budget", "/v1/admin/wildcards/recheck"):
        assert needle in README, needle


def test_readme_is_honest_about_what_was_not_verified():
    assert "not verified" in README.lower() and "real Panorama" in README and "Docker image build" in README


def test_a_dry_run_does_not_consume_its_sync_id(client):
    sync(client, ["a.example.com"], sync_id="plan-1", dry_run=True)
    real = sync(client, ["a.example.com"], sync_id="plan-1")
    assert real["duplicate"] is False and real["status"] == "applied" and feed(client).text == "a.example.com/\n"


def test_env_example_has_no_new_required_variables():
    text = Path(__file__).resolve().parent.parent.joinpath(".env.example").read_text()
    assert "SYNC" not in text.upper().replace("RESYNC", "")


def test_wildcard_policy_labels_are_documented_values(client):
    apex_policy(client)
    assert client.get("/v1/admin/wildcards", headers={"X-API-Key": "k"}).json()["policy"] == "apex-classification"
