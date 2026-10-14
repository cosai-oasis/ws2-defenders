"""Fetch CoSAI list archives from the groups.io API.

This is the input to `ingest/maillist.py`. Anyone with a groups.io account and their
own API key can run this module and get the same corpus, each list's full history.

## Why the API and not the public archive

The archives genuinely are public -- every CoSAI group page says "Archives are
publicly visible", and the site's own sitemap enumerates ~1,800 CoSAI topic URLs for
search engines to index. They are still not *scrapable*: every `/messages`, `/topic`
and `/message` URL redirects to a browser-fingerprint probe, `robots.txt` disallows
`/g/*/rss` for all user agents, and it carries the line "AI crawlers must obtain a
license to access any Groups.io data." Getting past that means defeating an anti-bot
control, so this module does not try. `GET /api/v1/downloadarchives` is the route
groups.io supports for the job, and it is better than scraping anyway: it returns a
zip holding one mbox, which is the format `maillist.parse_mbox` already reads.

## The key

Create a personal key at `<site>/settings/apikeys` and export it:

    export GROUPSIO_API_KEY=...

It is yours, scoped to your own membership, revocable without changing your password,
and it skips the login/CSRF/2FA dance entirely. Nothing about this module is specific
to one account -- the site comes from `registry/mail-lists.yaml` and the key from the
environment, so a second person runs the same command with their own key.

## The daily allowance is the real constraint

`downloadarchives` is rate limited to **one call per person per group per 24 hours**,
and the docs call it resource intensive. So this module keeps a manifest of what it
last pulled and refuses a second call inside the window rather than spending it on a
duplicate. `--force` overrides that, and will usually just earn an error from the API.

Each fetch is a full archive, overwriting the last. `start_msg_num`/`start_time` are
exposed because the API has them, but a delta archive would have to be appended to the
previous file to stay complete, and a partly-appended mbox is worse than a re-download
of a few hundred messages once a day.

## Two methods: `messages` (default) and `archive`

`downloadarchives` needs more than an ordinary member has: on the first live run
(2026-09-22) every group answered `inadequate_permissions`. `getmessages` needs only
`archives_visible`, which a public-archive group grants, and it worked on 2026-09-23
with the same key (TSC: 495 messages, back to its first post in August 2024). So
`messages` is the default and `archive` stays for anyone who has export rights.

`getmessages` returns JSON, not raw mail, so this module writes it out as the mbox
`maillist.parse_mbox` already reads, with only the fields the parser uses: the subject
with its `[list]` tag (the API returns it bare), `Date`, `Message-ID`, `List-Id` and a
plain-text body. Calendar attachments are *not* fetched: their `download_url` is a web
UI path, not an API one, and that route has not been cleared (see the scraping note
above). `maillist` reads the body's "When:" line instead, which gives start and end
but no iCalendar UID or RRULE. It is paged at 100 and has no daily allowance, so the
manifest's 24-hour window applies to `archive` only.

## What lands on disk

`data/mail/<group>.mbox`, gitignored because it is a fetched artifact, reproducible by
anyone with a key, not because of what is in it. CoSAI's lists are open OASIS lists:
their archives are a public record, TLP:CLEAR, like the GitHub repositories and the
contributor addresses those carry. Message bodies are written as the API returns them,
addresses included.
"""

from __future__ import annotations

import argparse
import email.utils
import io
import json
import mailbox
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable

from ..paths import MAIL, mail_api_parent, mail_lists, mail_site

API_KEY_ENV = "GROUPSIO_API_KEY"
SITE_ENV = "GROUPSIO_SITE"

# One call per person per group per 24 hours, per the endpoint's own documentation.
# Held here rather than discovered by getting refused, so a run that would be refused
# costs nothing and says why.
RATE_LIMIT = timedelta(hours=24)

MANIFEST_NAME = "manifest.json"

# HTTP 429 is the documented backoff signal. Three tries at 2s, 4s, 8s: enough for a
# transient limit, short enough that a genuinely exhausted allowance fails today
# rather than blocking the terminal for an hour.
RETRY_DELAYS = (2.0, 4.0, 8.0)

# A groups.io zip download starts with the local file header magic. The endpoint
# returns JSON on error with a 200 in some cases, so the body is what decides.
ZIP_MAGIC = b"PK\x03\x04"

METHODS = ("messages", "archive")

# getmessages pages; 100 is the size the live run used. A pause between pages keeps
# a full pull (eight lists, a few thousand messages) well clear of the throttle.
PAGE_SIZE = 100
PAGE_DELAY = 1.0

_TAGGED = re.compile(r"\[cosai[-\w]*\]", re.I)


class FetchError(RuntimeError):
    """A fetch that failed for a reason the caller should see whole."""


@dataclass
class Fetched:
    """One group's result, for the manifest and the run summary."""

    group: str
    path: Path
    bytes_written: int
    messages: int
    fetched_at: str


# --- configuration ----------------------------------------------------------------

def site() -> str:
    """The groups.io instance. Registry default, overridable for another deployment."""
    return os.environ.get(SITE_ENV, "").rstrip("/") or mail_site()


def api_key() -> str:
    """The caller's own API key, or an error naming where to create one."""
    key = os.environ.get(API_KEY_ENV, "").strip()
    if not key:
        raise FetchError(
            f"{API_KEY_ENV} is not set. Create a personal API key at "
            f"{site()}/settings/apikeys and export it:\n"
            f"    export {API_KEY_ENV}=...\n"
            "The key is scoped to your own membership and can be revoked without "
            "changing your password. See set-keys.example.sh."
        )
    return key


def api_group_name(group: str, parent: str | None = None) -> str:
    """The name the API resolves: `open-projects+cosai-tsc`, not `cosai-tsc`.

    The short name is what the web UI, the registry and the mbox filenames use; the API
    answers it with group_not_found. Already-qualified names pass through.
    """
    parent = mail_api_parent() if parent is None else parent
    if not parent or "+" in group:
        return group
    return f"{parent}+{group}"


def fetch_groups() -> list[dict]:
    """The lists marked `fetch: true` in registry/mail-lists.yaml."""
    return [entry for entry in mail_lists() if entry.get("fetch")]


# --- transport --------------------------------------------------------------------

# Injectable so tests exercise the retry, error and unzip paths without a network and
# without a key. Signature: (url, headers) -> (status, body).
Opener = Callable[[str, dict[str, str]], tuple[int, bytes]]


def _urlopen(url: str, headers: dict[str, str]) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:              # body carries the API reason
        return error.code, error.read()


def download_archive(group: str, *, key: str, base: str, opener: Opener = _urlopen,
                     start_msg_num: int | None = None,
                     start_time: str | None = None,
                     sleep: Callable[[float], None] = time.sleep) -> bytes:
    """One group's archive as zip bytes. Retries 429 only; other errors are final."""
    params: dict[str, str] = {"group_name": group}
    if start_msg_num is not None:
        params["start_msg_num"] = str(start_msg_num)
    if start_time is not None:
        params["start_time"] = start_time
    url = f"{base}/api/v1/downloadarchives?" + urllib.parse.urlencode(params)
    headers = {"Authorization": f"Bearer {key}", "Accept": "application/zip"}
    return _request(group, url, headers, ok=lambda body: body.startswith(ZIP_MAGIC),
                    expected="a zip", opener=opener, sleep=sleep)


def get_messages(group: str, *, key: str, base: str, opener: Opener = _urlopen,
                 page_size: int = PAGE_SIZE,
                 sleep: Callable[[float], None] = time.sleep) -> list[dict]:
    """Every message in a group, oldest first, following `next_page_token`."""
    headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    messages: list[dict] = []
    token = None
    while True:
        params = {"group_name": group, "limit": str(page_size)}
        if token is not None:
            params["page_token"] = str(token)
        url = f"{base}/api/v1/getmessages?" + urllib.parse.urlencode(params)
        page = json.loads(_request(group, url, headers, ok=_is_page,
                                   expected="a message page", opener=opener,
                                   sleep=sleep))
        messages.extend(page.get("data") or [])
        if not page.get("has_more"):
            break
        token = page.get("next_page_token")
        if not token:                  # stopping here would be a silent truncation
            raise FetchError(f"{group}: has_more with no next_page_token after "
                             f"{len(messages)} messages")
        sleep(PAGE_DELAY)
    total = page.get("total_count")
    if isinstance(total, int) and total != len(messages):
        # Mail posted mid-pull moves the count; say so rather than hide it.
        print(f"  note: {group} reported {total} messages, received {len(messages)}",
              file=sys.stderr)
    return messages


def _is_page(body: bytes) -> bool:
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return False
    return (isinstance(parsed, dict) and parsed.get("object") != "error"
            and isinstance(parsed.get("data"), list))


def _request(group: str, url: str, headers: dict[str, str], *,
             ok: Callable[[bytes], bool], expected: str, opener: Opener,
             sleep: Callable[[float], None]) -> bytes:
    """One API call's body. Retries 429 only; other errors are final."""
    last = ""
    for delay in (*RETRY_DELAYS, None):
        status, body = opener(url, headers)
        if status == 200 and ok(body):
            return body
        last = _explain(group, status, body, expected)
        # Only a rate limit is worth waiting out. A 401 or a bad group name will say
        # the same thing in eight seconds as it does now.
        if status != 429 or delay is None:
            break
        sleep(delay)
    raise FetchError(last)


def _explain(group: str, status: int, body: bytes, expected: str = "a zip") -> str:
    """A failure message that quotes the API rather than guessing at it."""
    text = body[:400].decode("utf-8", "replace").strip()
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict) and parsed.get("object") == "error":
            text = parsed.get("type", "") + (
                f": {parsed['extra']}" if parsed.get("extra") else "")
    except (ValueError, TypeError):
        pass
    hint = ""
    if status in (401, 403) or "unauthorized" in text:
        hint = (f"\n  Either {API_KEY_ENV} is wrong, or your account is not a member "
                f"of {group}. Public archives are readable on the web without a "
                "login, but the API authenticates every call.")
    elif status == 429 or "rate" in text.lower():
        hint = ("\n  downloadarchives allows one call per group per 24 hours. The "
                "manifest records when each group was last pulled.")
    elif "inadequate_permissions" in text:
        hint = ("\n  The key authenticates, but this call needs a permission your "
                "membership lacks. downloadarchives does; try --method messages.")
    elif status == 200:
        hint = f"\n  A 200 that is not {expected}: the API returned an error body."
    return f"{group}: HTTP {status} {text}{hint}"


# --- writing ----------------------------------------------------------------------

def extract_mbox(payload: bytes, dest: Path) -> int:
    """Write the single mbox inside the archive zip. Returns bytes written."""
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = [n for n in archive.namelist() if not n.endswith("/")]
        if not names:
            raise FetchError(f"empty archive zip for {dest.stem}")
        # Documented as one file in mbox format. If that ever changes, take the
        # largest rather than the first, and say so, instead of silently truncating.
        if len(names) > 1:
            names.sort(key=lambda n: archive.getinfo(n).file_size, reverse=True)
            print(f"  note: {len(names)} files in the zip, using {names[0]!r}",
                  file=sys.stderr)
        data = archive.read(names[0])
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return len(data)


def count_messages(path: Path) -> int:
    """Messages in an mbox, by counting `From ` separators at line starts.

    Cheap and good enough for the manifest and the run summary. `parse_mbox` is the
    thing that actually reads the file, and it counts for real.
    """
    total = 0
    with path.open("rb") as handle:
        for line in handle:
            if line.startswith(b"From "):
                total += 1
    return total


class _Text(HTMLParser):
    """HTML to plain text, keeping each link's target: summary pointers live there."""

    _BREAKS = {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "table"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._href: list[str | None] = []

    def handle_starttag(self, tag, attrs):
        if tag in self._BREAKS:
            self.parts.append("\n")
        if tag == "a":
            self._href.append(dict(attrs).get("href"))

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            href = self._href.pop()
            if href and href.startswith("http"):
                self.parts.append(f" <{href}>")
        elif tag in self._BREAKS:
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)


def html_to_text(markup: str) -> str:
    parser = _Text()
    parser.feed(markup)
    parser.close()
    text = "".join(parser.parts)
    text = re.sub(r"[ \t\xa0]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def _created(value: str) -> datetime | None:
    """groups.io timestamps carry nanoseconds; fromisoformat stops at micro."""
    trimmed = re.sub(r"(\.\d{6})\d+", r"\1", value or "")
    try:
        return datetime.fromisoformat(trimmed)
    except ValueError:
        return None


def to_mbox_message(message: dict, entry: dict, host: str) -> mailbox.mboxMessage:
    """One getmessages record as the mail `maillist` would have received.

    The subject gets the `[list]` tag the delivered copy carries, because the
    parser's `Now:` and dated-subject rules anchor on it and the API returns the
    subject bare. `List-Id` is the group's, which is what assigns the message to a
    list. No `From`: the record has a display name but no address, and the parser
    never reads it.
    """
    subject = (message.get("subject") or "").strip()
    if not _TAGGED.search(subject):
        subject = f"[{entry['canonical']}] {subject}"
    body = message.get("body") or ""
    if not message.get("is_plain_text"):
        body = html_to_text(body)

    mail = EmailMessage()
    mail["Subject"] = subject
    created = _created(message.get("created", ""))
    if created:
        mail["Date"] = email.utils.format_datetime(created)
    mail["Message-ID"] = f"<groupsio.{message.get('id')}@{host}>"
    mail["List-Id"] = f"<{entry['group']}.{host}>"
    mail["X-Groupsio-Msg-Num"] = str(message.get("msg_num", ""))
    mail["X-Groupsio-Topic-Id"] = str(message.get("topic_id", ""))
    mail["X-Cosai-Source"] = "groups.io getmessages (converted; not the raw message)"
    mail.set_content(body)

    boxed = mailbox.mboxMessage(mail)
    stamp = created.astimezone(timezone.utc) if created else datetime.now(timezone.utc)
    boxed.set_from("groups.io", stamp.timetuple())
    return boxed


def write_messages_mbox(messages: list[dict], entry: dict, dest: Path,
                        host: str) -> int:
    """Write the converted messages; returns bytes written.

    Built beside the destination and moved into place, so an interrupted run leaves
    the previous file whole rather than a half-written one.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(".mbox.partial")
    partial.unlink(missing_ok=True)
    box = mailbox.mbox(str(partial))
    try:
        for message in messages:
            box.add(to_mbox_message(message, entry, host))
        box.flush()
    finally:
        box.close()
    os.replace(partial, dest)
    return dest.stat().st_size


# --- manifest ---------------------------------------------------------------------

def manifest_path(dest_dir: Path) -> Path:
    return dest_dir / MANIFEST_NAME


def read_manifest(dest_dir: Path) -> dict[str, dict]:
    path = manifest_path(dest_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:                       # a truncated manifest must not block a run
        print(f"  note: unreadable manifest at {path}, starting fresh", file=sys.stderr)
        return {}


def write_manifest(dest_dir: Path, manifest: dict[str, dict]) -> None:
    manifest_path(dest_dir).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def within_rate_limit(entry: dict | None, now: datetime) -> bool:
    """True if this group was pulled recently enough that the API would refuse."""
    if not entry or not entry.get("fetched_at"):
        return False
    try:
        last = datetime.fromisoformat(entry["fetched_at"])
    except ValueError:
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return now - last < RATE_LIMIT


# --- the run ----------------------------------------------------------------------

def fetch_all(groups: list[dict], *, dest_dir: Path = MAIL, key: str | None = None,
              base: str | None = None, opener: Opener | None = None,
              force: bool = False, now: datetime | None = None,
              method: str = "archive",
              sleep: Callable[[float], None] = time.sleep) -> tuple[list[Fetched],
                                                                   list[str]]:
    """Fetch each group's mail. Returns what was written and what failed.

    `method` defaults to `archive` here and to `messages` on the command line; the
    function keeps the original behaviour for callers that predate the choice.

    One group's failure never aborts the others: a partial corpus with a named gap is
    more use than no corpus, and the gap is visible in both the summary and the
    manifest. What must not happen is a gap that reads as "no meetings that week" --
    hence `maillist`'s coverage windows, and hence the report below.
    """
    key = key or api_key()
    base = base or site()
    # Looked up now, not bound as a default, so a test that patches `_urlopen`
    # really does keep the CLI off the network.
    opener = opener or _urlopen
    now = now or datetime.now(timezone.utc)
    dest_dir.mkdir(parents=True, exist_ok=True)
    manifest = read_manifest(dest_dir)

    written: list[Fetched] = []
    failed: list[str] = []
    for entry in groups:
        group = entry["group"]
        dest = dest_dir / f"{group}.mbox"
        previous = manifest.get(group)
        # Only downloadarchives has the daily allowance; an entry from before the
        # method was recorded was an archive pull.
        limited = method == "archive" and (previous or {}).get("method",
                                                                "archive") == "archive"
        if not force and limited and dest.exists() and within_rate_limit(previous, now):
            last = manifest[group]["fetched_at"]
            print(f"  {group:<32} cached, pulled {last} (1/24h limit)")
            continue
        try:
            if method == "archive":
                payload = download_archive(api_group_name(group), key=key, base=base,
                                           opener=opener, sleep=sleep)
                size = extract_mbox(payload, dest)
            else:
                records = get_messages(api_group_name(group), key=key, base=base,
                                       opener=opener, sleep=sleep)
                size = write_messages_mbox(records, entry, dest,
                                           urllib.parse.urlsplit(base).hostname or "")
        except (FetchError, zipfile.BadZipFile) as error:
            failed.append(str(error))
            print(f"  {group:<32} FAILED", file=sys.stderr)
            continue
        messages = count_messages(dest)
        stamp = now.isoformat(timespec="seconds")
        manifest[group] = {"fetched_at": stamp, "bytes": size, "messages": messages,
                           "method": method, "canonical": entry["canonical"],
                           "workstream": entry["workstream"]}
        written.append(Fetched(group, dest, size, messages, stamp))
        print(f"  {group:<32} {messages:>5} messages  {size:>9} B")

    write_manifest(dest_dir, manifest)
    return written, failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Download CoSAI list archives from groups.io into data/mail/.")
    parser.add_argument("--group", action="append", dest="groups", metavar="NAME",
                        help="fetch one group by its groups.io name; repeatable. "
                             "Default: every list with fetch: true in the registry.")
    parser.add_argument("--dest", type=Path, default=MAIL,
                        help=f"where to write the mboxes (default: {MAIL})")
    parser.add_argument("--method", choices=METHODS, default="messages",
                        help="messages: page getmessages (member access, no daily "
                             "limit). archive: downloadarchives (needs export "
                             "rights, 1 call/group/24h). Default: messages.")
    parser.add_argument("--force", action="store_true",
                        help="ignore the recorded 24h window and call anyway")
    parser.add_argument("--list", action="store_true",
                        help="print the configured lists and exit, without a key")
    args = parser.parse_args(argv)

    if args.list:
        for entry in mail_lists():
            mark = "fetch" if entry.get("fetch") else "  -  "
            print(f"  [{mark}] {entry['group']:<32} {entry['title']}")
        return 0

    selected = fetch_groups()
    if args.groups:
        wanted = {name.lower() for name in args.groups}
        known = {entry["group"].lower(): entry for entry in mail_lists()}
        unknown = sorted(wanted - set(known))
        if unknown:
            print(f"not in registry/mail-lists.yaml: {', '.join(unknown)}",
                  file=sys.stderr)
            return 1
        selected = [known[name] for name in sorted(wanted)]

    try:
        written, failed = fetch_all(selected, dest_dir=args.dest, force=args.force,
                                    method=args.method)
    except FetchError as error:                  # a missing key, before any request
        print(error, file=sys.stderr)
        return 1

    total = sum(item.messages for item in written)
    print(f"\n{len(written)} archives, {total} messages -> {args.dest}")
    if failed:
        print(f"\n{len(failed)} failed:", file=sys.stderr)
        for line in failed:
            print(f"  {line}", file=sys.stderr)
        # Loud, because a missing list looks exactly like a quiet list downstream.
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
