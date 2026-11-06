# Release verification - EDL Publisher 2.3.1 + YAML importer 2.1.1

## Final artifacts
```
abcd8779702e37976f2027fd0e91e68c436165b0f8746ddaf69aa8b99b33b7d4  edl-service.tar.gz
eb63ffba1e387c519dc75cfba824bcda116ca2225345c364262eb620b64cb37a  edl_yaml_importer.zip
```
Hashes were taken before and after the verification run and are identical. Every result below is from fresh
extractions of exactly these two files, run with the development trees moved out of the way.

## What the evidence shows, and does not show
* "No development-workspace modules were imported": the in-process runs (1, 2, 4) load a plugin that fails the session
  if any entry of `sys.modules` has a file under the development trees; it reported `none` and printed that `app` and
  `import_edl` came from the extracted copies. The packaged-pair run (3) uses separate processes, so that plugin sees
  nothing there; for it the proof is that the server is started with its working directory in the extracted archive
  and the importer file is the extracted one, while the development trees did not exist at their normal paths (they were
  renamed for the run and restored afterwards). It is not an audit of every file the subprocesses read.
* PostgreSQL results are from a throw-away PostgreSQL 16.15 (Ubuntu package) cluster. Panorama was a mock in every run.
* Docker image build/compose were not tested. A real Panorama was not tested.

## Run log (script: final_verify.sh)
```
== artifact hashes (before)
abcd8779702e37976f2027fd0e91e68c436165b0f8746ddaf69aa8b99b33b7d4  <scratch>/dist/edl-service.tar.gz
eb63ffba1e387c519dc75cfba824bcda116ca2225345c364262eb620b64cb37a  <scratch>/dist/edl_yaml_importer.zip

== [PACKAGED] 1. server suite from the extracted archive
cd <scratch>/finalrun/srv/edl-service && python -m pytest tests -p devguard -p no:cacheprovider -q
..........                                                               [100%]
DEVGUARD imported-from: {'app': '<scratch>/finalrun/srv/edl-service/app/__init__.py'}
DEVGUARD modules from the development workspace: none
=============================== warnings summary ===============================
../../../venv/lib/python3.13/site-packages/fastapi/testclient.py:1
650 passed, 8 skipped, 1 warning in 45.28s

== [PACKAGED] 2. importer suite from the extracted ZIP, in-process against the extracted server tree
cd <scratch>/finalrun/imp/edl_yaml_importer && EDL_SERVER_SRC=<scratch>/finalrun/srv/edl-service python -m pytest tests -p devguard -p no:cacheprovider -q
.................................................                        [100%]
DEVGUARD imported-from: {'app': '<scratch>/finalrun/srv/edl-service/app/__init__.py', 'import_edl': '<scratch>/finalrun/imp/edl_yaml_importer/import_edl.py'}
DEVGUARD modules from the development workspace: none
=============================== warnings summary ===============================
tests/test_integration.py::test_initial_import_of_multiple_yaml_lists
109 passed, 12 skipped, 1 warning in 30.94s

== [PACKAGED PAIR] 3. extracted importer as a subprocess vs the server TAR started as a real uvicorn process
cd <scratch>/finalrun/imp/edl_yaml_importer && EDL_SERVER_ARCHIVE=<scratch>/dist/edl-service.tar.gz EDL_LEGACY_ARCHIVE=<scratch>/edl-service-2.2.0-delivered.tar.gz python -m pytest tests/test_packaged_pair.py -p devguard -p no:cacheprovider -v -s
============================= test session starts ==============================
platform linux -- Python 3.13.18, pytest-9.2.0, pluggy-1.7.0 -- <scratch>/venv/bin/python
rootdir: <scratch>/finalrun/imp/edl_yaml_importer
configfile: pytest.ini
plugins: anyio-4.16.0
collecting ... collected 12 items
tests/test_packaged_pair.py::test_packaged_server_is_the_expected_release_and_has_every_endpoint_the_importer_uses 
PACKAGED PAIR: server archive edl-service.tar.gz sha256 abcd8779702e3797 (app 2.3.1); importer <scratch>/finalrun/imp/edl_yaml_importer/import_edl.py sha256 33051b60ea80198a
PASSED
tests/test_packaged_pair.py::test_01_initial_64000_entry_import 01: importer peak RSS 60 MB
PASSED
tests/test_packaged_pair.py::test_02_identical_repeat_import_changes_nothing PASSED
tests/test_packaged_pair.py::test_03_duplicates_reach_the_server_with_no_deduplicate_and_it_prevents_duplicate_rows PASSED
tests/test_packaged_pair.py::test_04_delete_missing_removes_only_this_sources_entries_and_shows_the_count_first PASSED
tests/test_packaged_pair.py::test_05_without_delete_missing_nothing_is_removed PASSED
tests/test_packaged_pair.py::test_06_interrupted_chunk_upload_resumes_without_a_new_session_and_never_applies_early PASSED
tests/test_packaged_pair.py::test_07_reclassification_of_blocked_and_pending_entries PASSED
tests/test_packaged_pair.py::test_08_100000_entry_chunked_import 08: importer peak RSS 77 MB for 100,000 entries
PASSED
tests/test_packaged_pair.py::test_09_server_restart_during_an_incomplete_sync PASSED
tests/test_packaged_pair.py::test_11_the_packaged_server_enforces_max_removals_itself_and_the_importer_passes_it_on PASSED
tests/test_packaged_pair.py::test_10_against_the_previous_v220_archive_single_mode_works_and_unsupported_features_are_refused PASSED
DEVGUARD imported-from: {}
DEVGUARD modules from the development workspace: none
======================== 12 passed in 92.28s (0:01:32) =========================

== [PACKAGED, PostgreSQL 16] 4. PostgreSQL suite from the extracted archive
cd <scratch>/finalrun/srv/edl-service && EDL_PG_BIN=/usr/lib/postgresql/16/bin EDL_LEGACY_ARCHIVE=<scratch>/edl-service-2.2.0-delivered.tar.gz EDL_SERVER_DIR=<scratch>/finalrun/srv/edl-service python -m pytest tests/test_postgres.py -p devguard -p no:cacheprovider -v -s
rootdir: <scratch>/finalrun/srv/edl-service
plugins: anyio-4.16.0
collecting ... collected 8 items
tests/test_postgres.py::test_01_upgrade_from_2_2_0_keeps_data_ownership_and_resumes_the_backlog 
POSTGRESQL server_version 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)
PASSED
tests/test_postgres.py::test_02_chunked_sync_of_64000_entries 
SERVER TREE <scratch>/finalrun/srv/edl-service version 2.3.1 on PostgreSQL 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)
PASSED
tests/test_postgres.py::test_03_identical_repeat_changes_nothing PASSED
tests/test_postgres.py::test_04_deletion_ownership_and_the_removal_limit PASSED
tests/test_postgres.py::test_05_duplicates_inside_and_across_chunks PASSED
tests/test_postgres.py::test_06_interrupted_session_survives_a_hard_server_kill_and_resumes PASSED
tests/test_postgres.py::test_07_reclassification_job_is_persisted_and_finished_after_a_hard_restart PASSED
tests/test_postgres.py::test_08_concurrent_syncs_are_serialised_and_idempotent PASSED
DEVGUARD imported-from: {'app': '<scratch>/finalrun/srv/edl-service/app/__init__.py'}
DEVGUARD modules from the development workspace: none
=============================== warnings summary ===============================
../../../venv/lib/python3.13/site-packages/fastapi/testclient.py:1
======================== 8 passed, 1 warning in 58.84s =========================

== artifact hashes (after)
abcd8779702e37976f2027fd0e91e68c436165b0f8746ddaf69aa8b99b33b7d4  <scratch>/dist/edl-service.tar.gz
eb63ffba1e387c519dc75cfba824bcda116ca2225345c364262eb620b64cb37a  <scratch>/dist/edl_yaml_importer.zip
== done

```
