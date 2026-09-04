"""The on-disk response cache: a speed-up with an audit trail, never a source of truth.

No test here touches the network. `urlopen` is replaced with a fake server
that records what would have been sent and answers a matching If-None-Match
with 304, the way GitHub does.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import time
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from mcp_vet import http as http_mod
from mcp_vet.audit import audit_repository
from mcp_vet.cli import main
from mcp_vet.http import FetchError, NotFound, get_json

from helpers import mock_response, repo_json

URL = "https://api.github.com/repos/acme/widget-mcp"
URLOPEN = "mcp_vet.http.urllib.request.urlopen"


class FakeServer:
    """Serves one JSON body, optionally with an ETag; 304 on a matching If-None-Match."""

    def __init__(self, body, etag=None, status=200, raw=None):
        self.body = body
        self.etag = etag
        self.status = status
        self.raw = raw
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        if self.status != 200:
            raise urllib.error.HTTPError(req.full_url, self.status, "error", {}, None)
        if self.etag and req.get_header("If-none-match") == self.etag:
            raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", {}, None)
        response = mock_response(self.body)
        if self.raw is not None:
            response.__enter__.return_value.read.return_value = self.raw
        response.__enter__.return_value.headers = {"ETag": self.etag} if self.etag else {}
        return response


@pytest.fixture
def cache_on(monkeypatch):
    monkeypatch.setenv(http_mod.CACHE_ENV, "1")


def _sent_headers(req) -> dict:
    return dict(req.header_items())


class TestHitsAndMisses:
    def test_second_call_within_ttl_makes_no_request(self, cache_on):
        server = FakeServer(repo_json())
        with patch(URLOPEN, server):
            first = get_json(URL)
            second = get_json(URL)
        assert first == second == repo_json()
        assert len(server.requests) == 1
        stats = http_mod.cache_stats()
        assert (stats.requests, stats.hits, stats.stored) == (1, 1, 1)
        assert stats.oldest_seconds < 5

    def test_key_includes_the_query_string(self, cache_on):
        server = FakeServer({"page": 1})
        with patch(URLOPEN, server):
            get_json(URL + "/tags?per_page=100")
            get_json(URL + "/tags?per_page=50")
        assert len(server.requests) == 2

    def test_env_off_means_every_call_is_a_request(self, monkeypatch):
        monkeypatch.setenv(http_mod.CACHE_ENV, "0")
        server = FakeServer(repo_json())
        with patch(URLOPEN, server):
            get_json(URL)
            get_json(URL)
        assert len(server.requests) == 2
        assert http_mod.cache_stats().hits == 0
        assert not os.path.exists(http_mod.cache_dir())

    @pytest.mark.parametrize("value", ["0", "off", "false", "no", " No "])
    def test_every_spelling_of_off_is_off(self, monkeypatch, value):
        monkeypatch.setenv(http_mod.CACHE_ENV, value)
        assert http_mod.cache_enabled() is False

    def test_no_cache_override_beats_the_environment(self, cache_on):
        http_mod.set_cache_enabled(False)
        server = FakeServer(repo_json())
        with patch(URLOPEN, server):
            get_json(URL)
            get_json(URL)
        assert len(server.requests) == 2

    def test_per_call_opt_out(self, cache_on):
        server = FakeServer(repo_json())
        with patch(URLOPEN, server):
            get_json(URL, cache=False)
            get_json(URL, cache=False)
        assert len(server.requests) == 2

    def test_ttl_comes_from_the_environment_and_survives_nonsense(self, monkeypatch):
        monkeypatch.setenv(http_mod.CACHE_TTL_ENV, "120")
        assert http_mod.cache_ttl() == 120
        monkeypatch.setenv(http_mod.CACHE_TTL_ENV, "soon")
        assert http_mod.cache_ttl() == http_mod.DEFAULT_CACHE_TTL
        monkeypatch.setenv(http_mod.CACHE_TTL_ENV, "-5")
        assert http_mod.cache_ttl() == 0


class TestRevalidation:
    def test_expired_body_with_etag_is_reused_on_304(self, cache_on, monkeypatch):
        server = FakeServer(repo_json(), etag='"abc"')
        with patch(URLOPEN, server):
            get_json(URL)
            monkeypatch.setenv(http_mod.CACHE_TTL_ENV, "0")
            body = get_json(URL)
        assert body == repo_json()
        assert len(server.requests) == 2
        assert server.requests[1].get_header("If-none-match") == '"abc"'
        stats = http_mod.cache_stats()
        assert (stats.requests, stats.hits, stats.revalidated) == (2, 0, 1)

    def test_a_304_makes_the_entry_young_again(self, cache_on, monkeypatch):
        server = FakeServer(repo_json(), etag='"abc"')
        with patch(URLOPEN, server):
            get_json(URL)
            monkeypatch.setenv(http_mod.CACHE_TTL_ENV, "0")
            get_json(URL)                                   # 304
            monkeypatch.delenv(http_mod.CACHE_TTL_ENV)
            get_json(URL)                                   # hit, no request
        assert len(server.requests) == 2
        assert http_mod.cache_stats().hits == 1

    def test_expired_body_without_etag_is_fetched_again(self, cache_on, monkeypatch):
        server = FakeServer({"v": 1})
        with patch(URLOPEN, server):
            get_json(URL)
            server.body = {"v": 2}
            monkeypatch.setenv(http_mod.CACHE_TTL_ENV, "0")
            assert get_json(URL) == {"v": 2}
        assert len(server.requests) == 2
        assert "If-none-match" not in _sent_headers(server.requests[1])

    def test_a_changed_body_replaces_the_cached_one(self, cache_on, monkeypatch):
        server = FakeServer({"v": 1}, etag='"one"')
        with patch(URLOPEN, server):
            get_json(URL)
            server.body, server.etag = {"v": 2}, '"two"'   # stale ETag no longer matches
            monkeypatch.setenv(http_mod.CACHE_TTL_ENV, "0")
            assert get_json(URL) == {"v": 2}
            monkeypatch.delenv(http_mod.CACHE_TTL_ENV)
            assert get_json(URL) == {"v": 2}                # served from the new entry
        assert len(server.requests) == 2

    def test_a_304_with_nothing_cached_is_an_error_not_an_empty_answer(self, cache_on):
        def always_304(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", {}, None)
        with patch(URLOPEN, always_304):
            with pytest.raises(FetchError) as excinfo:
                get_json(URL)
        assert excinfo.value.status == 304


class TestWhatIsNeverCached:
    def test_server_errors(self, cache_on):
        server = FakeServer(None, status=500)
        with patch(URLOPEN, server):
            for _ in range(2):
                with pytest.raises(FetchError):
                    get_json(URL)
        assert len(server.requests) == 2
        assert not os.path.exists(http_mod._cache_path(URL))
        assert http_mod.cache_stats().requests == 2     # failed round trips still count

    def test_not_found(self, cache_on):
        server = FakeServer(None, status=404)
        with patch(URLOPEN, server):
            for _ in range(2):
                with pytest.raises(NotFound):
                    get_json(URL)
        assert len(server.requests) == 2

    def test_malformed_json(self, cache_on):
        server = FakeServer(None, raw=b"{not json")
        with patch(URLOPEN, server):
            for _ in range(2):
                with pytest.raises(FetchError):
                    get_json(URL)
        assert len(server.requests) == 2
        assert not os.path.exists(http_mod._cache_path(URL))


class TestOnDisk:
    def test_entry_is_private_and_holds_no_request_headers(self, cache_on):
        server = FakeServer(repo_json(), etag='"abc"')
        with patch(URLOPEN, server):
            get_json(URL, headers={"Authorization": "Bearer ghp_secret_value"})
        path = http_mod._cache_path(URL)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        assert "ghp_secret_value" not in text
        assert "Authorization" not in text
        entry = json.loads(text)
        assert entry["url"] == URL
        assert entry["etag"] == '"abc"'
        assert entry["body"] == repo_json()
        if sys.platform != "win32":
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
            assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700

    def test_corrupt_entry_is_discarded_and_rewritten(self, cache_on):
        path = http_mod._cache_path(URL)
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{garbage")
        server = FakeServer(repo_json())
        with patch(URLOPEN, server):
            assert get_json(URL) == repo_json()
        assert len(server.requests) == 1
        with open(path, encoding="utf-8") as handle:
            assert json.load(handle)["body"] == repo_json()

    def test_entry_naming_a_different_url_is_not_trusted(self, cache_on):
        path = http_mod._cache_path(URL)
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"format": 1, "url": "https://elsewhere.example/", "fetched_at": time.time(),
                       "etag": None, "body": {"planted": True}}, handle)
        server = FakeServer(repo_json())
        with patch(URLOPEN, server):
            assert get_json(URL) == repo_json()
        assert len(server.requests) == 1

    def test_entries_untouched_for_a_week_are_pruned_and_foreign_files_left_alone(self, cache_on):
        directory = http_mod.cache_dir()
        os.makedirs(directory)
        week_ago = time.time() - http_mod.CACHE_PRUNE_AFTER - 3600
        old = os.path.join(directory, "a" * 64 + ".json")
        fresh = os.path.join(directory, "b" * 64 + ".json")
        stale_tmp = os.path.join(directory, ".tmp-abc.json")
        foreign = os.path.join(directory, "notes.txt")
        for name in (old, fresh, stale_tmp, foreign):
            with open(name, "w") as handle:
                handle.write("x")
        for name in (old, stale_tmp, foreign):
            os.utime(name, (week_ago, week_ago))
        with patch(URLOPEN, FakeServer(repo_json())):
            get_json(URL)
        assert not os.path.exists(old)
        assert not os.path.exists(stale_tmp)
        assert os.path.exists(fresh)
        assert os.path.exists(foreign)

    def test_an_unwritable_cache_is_not_an_error(self, cache_on, monkeypatch, tmp_path):
        blocker = tmp_path / "file-where-a-directory-should-be"
        blocker.write_text("")
        monkeypatch.setenv(http_mod.CACHE_DIR_ENV, str(blocker))
        server = FakeServer(repo_json())
        with patch(URLOPEN, server):
            assert get_json(URL) == repo_json()
            assert get_json(URL) == repo_json()
        assert len(server.requests) == 2
        assert http_mod.cache_stats().stored == 0

    def test_default_location_is_under_the_xdg_cache_home(self, monkeypatch):
        monkeypatch.delenv(http_mod.CACHE_DIR_ENV)
        monkeypatch.setenv("XDG_CACHE_HOME", "/somewhere/cache")
        assert http_mod.cache_dir() == os.path.join("/somewhere/cache", "mcp-vet")


class TestAgeText:
    @pytest.mark.parametrize("seconds, text", [
        (0, "under a minute old"), (59, "under a minute old"), (60, "1 minute old"),
        (754, "12 minutes old"), (5400, "1.5 hours old"),
    ])
    def test_reads_like_a_person_wrote_it(self, seconds, text):
        assert http_mod.age_text(seconds) == text


class TestCommandLine:
    @patch(URLOPEN)
    def test_check_notes_cached_answers_and_no_cache_bypasses_them(self, urlopen, cache_on, capsys):
        urlopen.return_value = mock_response(repo_json())
        main(["check", "acme/widget-mcp"])
        assert urlopen.call_count == 1
        assert "local cache" not in capsys.readouterr().out

        main(["check", "acme/widget-mcp"])
        assert urlopen.call_count == 1
        assert "1 response(s) came from the local cache" in capsys.readouterr().out

        main(["check", "--no-cache", "acme/widget-mcp"])
        assert urlopen.call_count == 2
        assert "local cache" not in capsys.readouterr().out

    @patch(URLOPEN)
    def test_the_flag_is_accepted_after_the_positional_too(self, urlopen, cache_on):
        urlopen.return_value = mock_response(repo_json())
        main(["check", "acme/widget-mcp"])
        main(["check", "acme/widget-mcp", "--no-cache"])
        assert urlopen.call_count == 2

    @patch(URLOPEN)
    def test_no_cache_does_not_leak_into_the_next_invocation(self, urlopen, cache_on):
        urlopen.return_value = mock_response(repo_json())
        main(["check", "--no-cache", "acme/widget-mcp"])
        assert http_mod.cache_enabled() is True

    @patch(URLOPEN)
    def test_report_stays_pure_json_with_the_note_inside(self, urlopen, cache_on, capsys):
        urlopen.return_value = mock_response(repo_json())
        main(["report", "acme/widget-mcp", "--no-registry"])
        capsys.readouterr()
        main(["report", "acme/widget-mcp", "--no-registry"])
        out = capsys.readouterr().out
        data = json.loads(out)                     # nothing printed outside the document
        assert data["notes"]["network"]["cache_hits"] == 4
        assert data["notes"]["network"]["requests"] == 0
        assert any("came from the local cache" in line for line in data["limitations"])

    def test_every_network_command_accepts_the_flag(self):
        from mcp_vet.cli import build_parser
        parser = build_parser()
        for argv in (["search", "x", "--no-cache"], ["registry", "x", "--no-cache"],
                     ["check", "a/b", "--no-cache"], ["audit", "a/b", "--no-cache"],
                     ["diff", "a/b", "v1", "v2", "--no-cache"], ["report", "a/b", "--no-cache"]):
            assert parser.parse_args(argv).no_cache is True


class TestAuditReport:
    @patch(URLOPEN)
    def test_first_audit_is_live_and_the_second_says_it_was_cached(self, urlopen, cache_on):
        urlopen.return_value = mock_response(repo_json())
        live = audit_repository("acme/widget-mcp", check_registry=False)
        cached = audit_repository("acme/widget-mcp", check_registry=False)

        assert live.notes["network"] == {
            "requests": 4, "cache_hits": 0, "revalidated": 0, "cache_oldest_seconds": 0,
        }
        assert not any("local cache" in line for line in live.limitations)

        assert cached.notes["network"]["cache_hits"] == 4
        assert cached.notes["network"]["requests"] == 0
        assert any(
            "4 of 4 API responses came from the local cache" in line
            for line in cached.limitations
        )

    @patch(URLOPEN)
    def test_revalidated_answers_are_live_and_not_a_limitation(self, urlopen, cache_on, monkeypatch):
        server = FakeServer(repo_json(), etag='"same"')
        urlopen.side_effect = server
        audit_repository("acme/widget-mcp", check_registry=False)
        monkeypatch.setenv(http_mod.CACHE_TTL_ENV, "0")
        report = audit_repository("acme/widget-mcp", check_registry=False)
        assert report.notes["network"]["revalidated"] == 4
        assert report.notes["network"]["cache_hits"] == 0
        assert not any("local cache" in line for line in report.limitations)
