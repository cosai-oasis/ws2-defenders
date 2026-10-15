"""The groups.io archive fetcher.

No test touches the network or needs a key: `download_archive` and `fetch_all` take an
injectable opener, so the retry, error, unzip and rate-limit paths are all exercised
against fakes. That is deliberate -- the endpoint allows one call per group per 24
hours, so a test suite that really called it would exhaust the allowance of whoever
ran it and then fail for the wrong reason.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bubo_graphrag.ingest import groupsio as G

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)

MBOX = (b"From nobody@example.invalid Mon Sep  1 00:00:00 2026\n"
        b"Date: Mon, 1 Sep 2026 00:00:00 +0000\n"
        b"List-Id: <cosai-defenders-ws.lists.oasis-open-projects.org>\n"
        b"Subject: [cosai-defenders] Now: CoSAI WS2 Meeting - Thursday, 3 September 2026\n"
        b"\n"
        b"body\n"
        b"\n"
        b"From nobody@example.invalid Mon Sep  8 00:00:00 2026\n"
        b"Date: Mon, 8 Sep 2026 00:00:00 +0000\n"
        b"List-Id: <cosai-defenders-ws.lists.oasis-open-projects.org>\n"
        b"Subject: [cosai-defenders] Cancelled Event: CoSAI WS2 Meeting\n"
        b"\n"
        b"body\n")


def zip_of(name: str = "cosai-defenders-ws.mbox", data: bytes = MBOX) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def opener_returning(*responses):
    """A fake opener yielding each (status, body) in turn, recording its calls."""
    calls: list[tuple[str, dict]] = []
    queue = list(responses)

    def opener(url, headers):
        calls.append((url, headers))
        return queue.pop(0) if len(queue) > 1 else queue[0]

    opener.calls = calls
    return opener


def entry(group: str = "cosai-defenders-ws") -> dict:
    return {"group": group, "canonical": "cosai-defenders",
            "workstream": "ws2-defenders", "fetch": True}


# --- the registry is the source of both the fetch set and the allowlist -----------

def test_the_registry_drives_both_the_fetch_set_and_the_parser_allowlist():
    """One file, or a list could be downloadable but unparseable."""
    from bubo_graphrag.ingest.maillist import KNOWN_LISTS
    from bubo_graphrag.paths import mail_lists

    for item in mail_lists():
        for spelling in item["spellings"]:
            assert KNOWN_LISTS[spelling] == (item["canonical"], item["workstream"])
    fetched = {item["group"] for item in G.fetch_groups()}
    assert fetched <= {item["group"] for item in mail_lists()}


def test_the_ws_suffix_and_the_bare_tag_map_to_one_list():
    """List-Id keeps `-ws`; the subject tag drops it. Split them and every count halves."""
    from bubo_graphrag.ingest.maillist import KNOWN_LISTS

    assert KNOWN_LISTS["cosai-defenders-ws"] == KNOWN_LISTS["cosai-defenders"]
    assert KNOWN_LISTS["cosai-risk-governance-ws"] == KNOWN_LISTS["cosai-risk-governance"]


def test_the_four_workstreams_the_two_boards_and_the_general_list_are_fetched():
    groups = {item["group"] for item in G.fetch_groups()}
    assert {"cosai-supply-chain-ws", "cosai-defenders-ws", "cosai-risk-governance-ws",
            "cosai-agentic-systems-ws", "cosai-tsc", "cosai-pgb", "cosai-op",
            "cosai-marketing"} <= groups


# --- authentication ---------------------------------------------------------------

def test_a_missing_key_names_the_page_that_creates_one(monkeypatch):
    monkeypatch.delenv(G.API_KEY_ENV, raising=False)
    with pytest.raises(G.FetchError) as raised:
        G.api_key()
    assert "/settings/apikeys" in str(raised.value)


def test_the_key_rides_in_an_authorization_header_not_the_url():
    """A key in a query string lands in server logs and in shell history."""
    opener = opener_returning((200, zip_of()))
    G.download_archive("cosai-tsc", key="SECRET", base="https://example.invalid",
                       opener=opener)
    url, headers = opener.calls[0]
    assert "SECRET" not in url
    assert headers["Authorization"] == "Bearer SECRET"


def test_the_api_is_asked_for_the_subgroup_name_not_the_short_one(tmp_path):
    """`cosai-tsc` is group_not_found to the API; only `open-projects+cosai-tsc` resolves.

    Every group failed on the first live run for exactly this reason. The mbox and the
    manifest keep the short name, which is what the web UI and the parser use.
    """
    opener = opener_returning((200, zip_of("cosai-tsc.mbox")))
    written, _ = G.fetch_all([entry("cosai-tsc")], dest_dir=tmp_path, key="k",
                             base="https://x.invalid", opener=opener, now=NOW)
    url, _ = opener.calls[0]
    assert "group_name=open-projects%2Bcosai-tsc" in url
    assert written[0].path.name == "cosai-tsc.mbox"
    assert G.api_group_name("open-projects+cosai-tsc") == "open-projects+cosai-tsc"


def test_the_site_comes_from_the_registry_so_nothing_is_hardcoded_to_one_account(
        monkeypatch):
    monkeypatch.delenv(G.SITE_ENV, raising=False)
    assert G.site() == "https://lists.oasis-open-projects.org"
    monkeypatch.setenv(G.SITE_ENV, "https://lists.example.invalid/")
    assert G.site() == "https://lists.example.invalid"


# --- failure is reported, never guessed at ----------------------------------------

def test_an_unauthorized_reply_is_quoted_and_explained():
    body = b'{"object":"error","type":"unauthorized_error","extra":""}'
    opener = opener_returning((401, body))
    with pytest.raises(G.FetchError) as raised:
        G.download_archive("cosai-tsc", key="k", base="https://x.invalid", opener=opener)
    message = str(raised.value)
    assert "unauthorized_error" in message and "not a member" in message


def test_a_two_hundred_that_is_not_a_zip_is_a_failure_not_an_empty_archive():
    """groups.io answers some errors with a 200 and a JSON body."""
    opener = opener_returning((200, b'{"object":"error","type":"bad_request"}'))
    with pytest.raises(G.FetchError) as raised:
        G.download_archive("cosai-tsc", key="k", base="https://x.invalid", opener=opener)
    assert "not a zip" in str(raised.value)


def test_only_a_rate_limit_is_retried():
    slept: list[float] = []
    opener = opener_returning((429, b"slow down"), (429, b"slow down"),
                              (200, zip_of()))
    G.download_archive("cosai-tsc", key="k", base="https://x.invalid", opener=opener,
                       sleep=slept.append)
    assert len(opener.calls) == 3 and slept == [2.0, 4.0]

    opener = opener_returning((401, b"nope"))
    with pytest.raises(G.FetchError):
        G.download_archive("cosai-tsc", key="k", base="https://x.invalid",
                           opener=opener, sleep=slept.append)
    assert len(opener.calls) == 1, "a 401 says the same thing in eight seconds"


# --- unzipping --------------------------------------------------------------------

def test_the_mbox_is_extracted_from_the_zip(tmp_path):
    dest = tmp_path / "cosai-defenders-ws.mbox"
    written = G.extract_mbox(zip_of(), dest)
    assert dest.read_bytes() == MBOX and written == len(MBOX)


def test_an_empty_zip_fails_rather_than_writing_nothing(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w"):
        pass
    with pytest.raises(G.FetchError):
        G.extract_mbox(buffer.getvalue(), tmp_path / "x.mbox")


def test_messages_are_counted_from_the_mbox_separators(tmp_path):
    path = tmp_path / "a.mbox"
    path.write_bytes(MBOX)
    assert G.count_messages(path) == 2


# --- the daily allowance ----------------------------------------------------------

def test_a_second_call_inside_the_window_is_skipped_not_spent(tmp_path):
    opener = opener_returning((200, zip_of()))
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW)
    assert len(opener.calls) == 1

    written, failed = G.fetch_all([entry()], dest_dir=tmp_path, key="k",
                                  base="https://x.invalid", opener=opener,
                                  now=NOW + timedelta(hours=3))
    assert len(opener.calls) == 1 and written == [] and failed == []


def test_the_window_reopens_after_twenty_four_hours(tmp_path):
    opener = opener_returning((200, zip_of()))
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW)
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW + timedelta(hours=25))
    assert len(opener.calls) == 2


def test_force_spends_the_call_anyway(tmp_path):
    opener = opener_returning((200, zip_of()))
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW)
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW, force=True)
    assert len(opener.calls) == 2


def test_a_missing_mbox_reopens_the_window_even_inside_it(tmp_path):
    """The manifest alone is not evidence: a deleted archive has to be refetchable."""
    opener = opener_returning((200, zip_of()))
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW)
    (tmp_path / "cosai-defenders-ws.mbox").unlink()
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW + timedelta(minutes=1))
    assert len(opener.calls) == 2


def test_an_unreadable_manifest_does_not_block_a_run(tmp_path):
    (tmp_path / G.MANIFEST_NAME).write_text("{ truncated")
    opener = opener_returning((200, zip_of()))
    written, failed = G.fetch_all([entry()], dest_dir=tmp_path, key="k",
                                  base="https://x.invalid", opener=opener, now=NOW)
    assert len(written) == 1 and failed == []


# --- a gap must never read as a quiet list ----------------------------------------

def test_one_groups_failure_does_not_abort_the_others_and_is_named(tmp_path):
    opener = opener_returning((401, b'{"object":"error","type":"unauthorized_error"}'),
                              (200, zip_of("cosai-tsc.mbox")))
    written, failed = G.fetch_all([entry(), entry("cosai-tsc")], dest_dir=tmp_path,
                                  key="k", base="https://x.invalid", opener=opener,
                                  now=NOW)
    assert [item.group for item in written] == ["cosai-tsc"]
    assert len(failed) == 1 and "cosai-defenders-ws" in failed[0]


def test_a_failed_group_is_absent_from_the_manifest_not_recorded_as_empty(tmp_path):
    """An entry saying "0 messages" would be indistinguishable from a quiet list."""
    opener = opener_returning((401, b"no"))
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW)
    manifest = json.loads((tmp_path / G.MANIFEST_NAME).read_text())
    assert "cosai-defenders-ws" not in manifest


def test_the_manifest_records_what_was_pulled(tmp_path):
    opener = opener_returning((200, zip_of()))
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW)
    record = json.loads((tmp_path / G.MANIFEST_NAME).read_text())["cosai-defenders-ws"]
    assert record["messages"] == 2
    assert record["canonical"] == "cosai-defenders"
    assert record["fetched_at"].startswith("2026-09-22T12:00:00")


def test_the_cli_exits_nonzero_when_a_group_failed(tmp_path, monkeypatch, capsys):
    """A partial corpus that exits 0 is a silent gap in a downstream build."""
    monkeypatch.setenv(G.API_KEY_ENV, "k")
    monkeypatch.setattr(G, "_urlopen", lambda url, headers: (401, b"no"))
    assert G.main(["--group", "cosai-tsc", "--dest", str(tmp_path)]) == 1


def test_the_cli_rejects_a_group_that_is_not_in_the_registry(tmp_path, monkeypatch):
    monkeypatch.setenv(G.API_KEY_ENV, "k")
    assert G.main(["--group", "not-a-list", "--dest", str(tmp_path)]) == 1


def test_list_works_without_a_key(monkeypatch, capsys):
    monkeypatch.delenv(G.API_KEY_ENV, raising=False)
    assert G.main(["--list"]) == 0
    assert "cosai-defenders-ws" in capsys.readouterr().out


# --- the fetched archives feed the existing parser unchanged ----------------------

def test_the_downloaded_archives_parse_as_one_corpus(tmp_path):
    """The point of the re-point: same parser, several lists, merged coverage."""
    from bubo_graphrag.ingest.maillist import mbox_paths, parse_mboxes

    tsc = MBOX.replace(b"cosai-defenders-ws.lists", b"cosai-tsc.lists") \
              .replace(b"[cosai-defenders]", b"[cosai-tsc]")
    opener = opener_returning((200, zip_of()), (200, zip_of("cosai-tsc.mbox", tsc)))
    G.fetch_all([entry(), entry("cosai-tsc")], dest_dir=tmp_path, key="k",
                base="https://x.invalid", opener=opener, now=NOW)

    parse = parse_mboxes(mbox_paths(tmp_path))
    assert parse.total_seen == 4
    assert parse.dropped_not_cosai == 0
    assert set(parse.coverage) == {"cosai-defenders", "cosai-tsc"}


def test_a_single_mbox_still_works(tmp_path):
    """A manual archive download needs no directory ceremony."""
    from bubo_graphrag.ingest.maillist import mbox_paths, parse_mboxes

    path = tmp_path / "one.mbox"
    path.write_bytes(MBOX)
    assert mbox_paths(path) == [path]
    assert parse_mboxes([path]).total_seen == 2


# --- the messages method: getmessages JSON written as the parser's mbox -----------

EVENT_BODY = ("<p>CoSAI TSC meeting</p><p>When:</p><p>Tuesday, 11 March 2025</p>"
              "<p>12:00pm to 1:00pm</p><p>(UTC-04:00) America/New York</p>"
              "<p>Organizer: Jane Doe <a href=\"mailto:jane@example.com\">"
              "jane@example.com</a></p>"
              "<p><a href=\"https://docs.google.com/document/d/abcdefghijklmnopqrstuvwxyz\">"
              "Minutes</a></p><p>quoted: jdoe@...&gt; wrote:</p>")


def record(num: int, subject: str, body: str = "<p>hello</p>",
           created: str = "2025-03-11T09:00:05.123456789-07:00") -> dict:
    return {"id": 1000 + num, "msg_num": num, "topic_id": 7, "subject": subject,
            "body": body, "is_plain_text": False, "created": created}


def page(items: list[dict], *, more: bool = False, token=None, total=None) -> tuple:
    body = {"object": "list", "data": items, "has_more": more,
            "next_page_token": token, "total_count": total}
    return 200, json.dumps(body).encode()


def test_every_page_is_followed_until_has_more_is_false():
    slept: list[float] = []
    opener = opener_returning(page([record(1, "a")], more=True, token=1, total=2),
                              page([record(2, "b")], total=2))
    got = G.get_messages("open-projects+cosai-tsc", key="k", base="https://x.invalid",
                         opener=opener, sleep=slept.append)
    assert [m["msg_num"] for m in got] == [1, 2]
    assert "page_token" not in opener.calls[0][0]
    assert "page_token=1" in opener.calls[1][0]
    assert slept == [G.PAGE_DELAY]


def test_has_more_without_a_token_fails_rather_than_truncating():
    opener = opener_returning(page([record(1, "a")], more=True, token=None))
    with pytest.raises(G.FetchError) as raised:
        G.get_messages("g", key="k", base="https://x.invalid", opener=opener,
                       sleep=lambda _: None)
    assert "next_page_token" in str(raised.value)


def test_an_error_body_on_a_page_is_a_failure_quoting_extra():
    """The `extra` field names the missing permission when groups.io sets it."""
    body = b'{"object":"error","type":"inadequate_permissions","extra":"archives"}'
    opener = opener_returning((200, body))
    with pytest.raises(G.FetchError) as raised:
        G.get_messages("g", key="k", base="https://x.invalid", opener=opener)
    assert "inadequate_permissions: archives" in str(raised.value)


def test_a_converted_message_carries_the_tag_list_id_and_date_the_parser_needs():
    msg = G.to_mbox_message(record(5, "Now: CoSAI TSC meeting - Tuesday, 11 March 2025"),
                            entry("cosai-tsc") | {"canonical": "cosai-tsc"},
                            "lists.oasis-open-projects.org")
    assert msg["Subject"] == "[cosai-tsc] Now: CoSAI TSC meeting - Tuesday, 11 March 2025"
    assert msg["List-Id"] == "<cosai-tsc.lists.oasis-open-projects.org>"
    assert msg["Date"] == "Tue, 11 Mar 2025 09:00:05 -0700"
    assert msg["Message-ID"] == "<groupsio.1005@lists.oasis-open-projects.org>"


def test_a_subject_already_tagged_is_not_tagged_twice():
    msg = G.to_mbox_message(record(1, "Re: [cosai-tsc] hello"), entry("cosai-tsc"),
                            "h.invalid")
    assert msg["Subject"] == "Re: [cosai-tsc] hello"


def test_the_body_is_written_whole_with_its_link_targets(tmp_path):
    """Open-list archives are TLP:CLEAR: the body is kept as sent, not redacted.

    Link targets must survive the HTML-to-text step, because summary pointers are
    hrefs whose visible text is only "Minutes".
    """
    dest = tmp_path / "cosai-tsc.mbox"
    G.write_messages_mbox([record(1, "Event: x", EVENT_BODY)], entry("cosai-tsc"),
                          dest, "lists.oasis-open-projects.org")
    text = dest.read_text()
    assert "jane@example.com" in text and "jdoe@..." in text
    assert "https://docs.google.com/document/d/abcdefghijklmnopqrstuvwxyz" in text


def test_the_messages_method_ignores_the_archive_allowance(tmp_path):
    """getmessages has no daily cap, so a rerun is a rerun, not a skipped call."""
    opener = opener_returning(page([record(1, "hello")]))
    for hours in (0, 1):
        G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                    opener=opener, now=NOW + timedelta(hours=hours), method="messages")
    assert len(opener.calls) == 2
    record_ = json.loads((tmp_path / G.MANIFEST_NAME).read_text())["cosai-defenders-ws"]
    assert record_["method"] == "messages" and record_["messages"] == 1


def test_a_messages_pull_does_not_reopen_or_close_the_archive_window(tmp_path):
    """An archive pull right after a messages pull still gets its one call."""
    opener = opener_returning(page([record(1, "hello")]), (200, zip_of()))
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW, method="messages")
    G.fetch_all([entry()], dest_dir=tmp_path, key="k", base="https://x.invalid",
                opener=opener, now=NOW, method="archive")
    assert len(opener.calls) == 2


def test_the_cli_defaults_to_the_messages_method(tmp_path, monkeypatch):
    monkeypatch.setenv(G.API_KEY_ENV, "k")
    calls: list[str] = []
    monkeypatch.setattr(G, "_urlopen",
                        lambda url, headers: (calls.append(url), page([]))[1])
    assert G.main(["--group", "cosai-tsc", "--dest", str(tmp_path)]) == 0
    assert "/api/v1/getmessages?" in calls[0]


def test_a_messages_pull_parses_into_timed_occurrences(tmp_path):
    """End to end: JSON in, meetings out, with times from the body's When line."""
    from bubo_graphrag.ingest.maillist import mbox_paths, parse_mboxes

    opener = opener_returning(page([
        record(1, "Now: CoSAI TSC meeting - Tuesday, 11 March 2025", EVENT_BODY),
        record(2, "Cancelled Event: CoSAI TSC meeting - Tuesday, 18 March 2025",
               EVENT_BODY.replace("11 March", "18 March"))]))
    G.fetch_all([{"group": "cosai-tsc", "canonical": "cosai-tsc", "workstream": "tsc",
                  "fetch": True}], dest_dir=tmp_path, key="k",
                base="https://lists.oasis-open-projects.org", opener=opener, now=NOW,
                method="messages")
    parse = parse_mboxes(mbox_paths(tmp_path))
    assert parse.dropped_not_cosai == 0
    held, canceled = parse.occurrences
    assert held.series_name == canceled.series_name == "CoSAI TSC meeting"
    assert held.starts_at == "2025-03-11T16:00:00+00:00"
    assert held.ends_at == "2025-03-11T17:00:00+00:00"
    assert held.evidence == "body-when"
    assert canceled.canceled and canceled.starts_at.startswith("2025-03-18T16:00")
