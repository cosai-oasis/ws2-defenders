"""Ingest the coalitionforsecureai.org RSS feed into its own named graph.

Source: ``https://www.coalitionforsecureai.org/feed/``, the WordPress feed of CoSAI's
site, paged with ``?paged=N`` back to the site's first post. It is the only feed read:
the site is CoSAI's own record of what it published, and an item or redirect leading to
any other host is refused rather than followed.

## What a post records, and what it does not

Each item becomes a ``cosaic:WebsitePost`` -- a ``BlogPost`` or ``PressRelease`` too
where the site files it so -- with the site's post ID, its URL, its categories, the
exact publication time, a dated ``PublicationEvent``, and ``linksTo`` edges to the CoSAI
works its body links to.

It records **no authorship**. The feed's ``dc:creator`` is the account that posted the
item -- one OASIS staff account for 59 of 60 posts -- so it is never read, and a byline
in the body is prose rather than a credit list. Until a direct rule says how a post's
authorship is established, this module emits no Person and no role, and the website
graph's shape rejects both.

## Why the feed is cached, and what a fetch can show

The raw pages are cached under ``data/vendor/coalitionforsecureai-feed/`` with the fetch
date, so a build is reproducible offline and a refresh is a deliberate act. A feed shows
the site as it stands: an edited post shows only its current form and a deleted one is
gone, so the graph's ``FeedCoverageWindow`` records the fetch date, and outside it the
absence of a post is not evidence that none was published.

Run:  python -m bubo_graphrag.ingest.website            # build from the cache
      python -m bubo_graphrag.ingest.website --refresh  # fetch the feed again first
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import Path

from rdflib import Graph, Literal, Namespace, RDF, RDFS, URIRef, XSD

from ..paths import DATA, ONTOLOGY, REPORTS

COSAIC = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")
OBO = Namespace("http://purl.obolibrary.org/obo/")
HAS_PARTICIPANT = OBO.BFO_0000057
OCCUPIES_TEMPORAL_REGION = OBO.BFO_0000199

SITE_HOST = "www.coalitionforsecureai.org"
FEED_URL = f"https://{SITE_HOST}/feed/"
CACHE = DATA / "vendor" / "coalitionforsecureai-feed"
WEBSITE_TTL = ONTOLOGY / "website.ttl"
USER_AGENT = "bubo (feed reader)"

_NS = {"content": "http://purl.org/rss/1.0/modules/content/"}
# The site's own categories that map to a subclass. Every other category is kept as a
# cosaic:siteCategory literal only.
CATEGORY_CLASS = {"Blog Post": COSAIC.BlogPost, "Press Release": COSAIC.PressRelease}
_POST_ID = re.compile(r"[?&]p=(\d+)\b")
_HREF = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.I)


@dataclass
class Post:
    post_id: str
    title: str
    url: str
    published_at: dt.datetime               # UTC
    categories: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


@dataclass
class Feed:
    posts: list[Post]
    fetched_on: str                         # ISO date
    refused: list[str] = field(default_factory=list)   # items not on the site


# --- fetching ------------------------------------------------------------------------

def _on_site(url: str) -> bool:
    return urllib.parse.urlsplit(url).netloc.lower() == SITE_HOST


def fetch(cache: Path = CACHE) -> Path:
    """Fetch every page of the feed into `cache`, replacing what was there.

    Stops at the first page the site answers 404, which is how WordPress ends a paged
    feed. A redirect off the site is refused: this module reads one feed only.
    """
    pages: list[bytes] = []
    for number in range(1, 200):
        url = FEED_URL + (f"?paged={number}" if number > 1 else "")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if not _on_site(response.geturl()):
                    raise RuntimeError(f"feed redirected off the site: {response.geturl()}")
                pages.append(response.read())
        except urllib.error.HTTPError as error:
            if error.code == 404 and number > 1:
                break
            raise
    cache.mkdir(parents=True, exist_ok=True)
    for old in cache.glob("page-*.xml"):
        old.unlink()
    for number, data in enumerate(pages, start=1):
        (cache / f"page-{number:03d}.xml").write_bytes(data)
    (cache / "manifest.json").write_text(json.dumps({
        "feed": FEED_URL, "pages": len(pages),
        "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }, indent=2) + "\n", encoding="utf-8")
    return cache


# --- parsing -------------------------------------------------------------------------

def parse_pages(pages: list[bytes], fetched_on: str) -> Feed:
    """Posts from raw feed pages. dc:creator is deliberately never read."""
    posts: dict[str, Post] = {}
    refused: list[str] = []
    for data in pages:
        root = ET.fromstring(data)
        for item in root.findall("./channel/item"):
            url = (item.findtext("link") or "").strip()
            guid = (item.findtext("guid") or "").strip()
            found = _POST_ID.search(guid)
            if not _on_site(url) or not found:
                refused.append(url or guid or "(item with no link)")
                continue
            body = item.findtext("content:encoded", namespaces=_NS) or ""
            links = sorted({html.unescape(h).strip() for h in _HREF.findall(body)})
            post = Post(
                post_id=found.group(1),
                title=html.unescape((item.findtext("title") or "").strip()),
                url=url,
                published_at=parsedate_to_datetime(item.findtext("pubDate"))
                .astimezone(dt.timezone.utc),
                categories=sorted({(c.text or "").strip() for c in item.findall("category")
                                   if (c.text or "").strip()}),
                links=links,
            )
            posts.setdefault(post.post_id, post)     # pages can overlap during a publish
    ordered = sorted(posts.values(), key=lambda p: (p.published_at, p.post_id))
    return Feed(posts=ordered, fetched_on=fetched_on, refused=refused)


def load_cache(cache: Path = CACHE) -> Feed:
    manifest = json.loads((cache / "manifest.json").read_text(encoding="utf-8"))
    pages = [path.read_bytes() for path in sorted(cache.glob("page-*.xml"))]
    return parse_pages(pages, manifest["fetched_at"][:10])


# --- linking posts to works -------------------------------------------------------------

def _url_key(url: str) -> str:
    """A URL folded for matching: no scheme, www, query, fragment or trailing slash;
    percent-encoding decoded; lowercased."""
    parts = urllib.parse.urlsplit(url.strip())
    host = parts.netloc.lower().removeprefix("www.")
    path = urllib.parse.unquote(parts.path).rstrip("/")
    return f"{host}{path}".lower()


def work_url_forms() -> dict[str, str]:
    """URL key -> work id, from each publication's registered URL forms and each
    citation stub's document URL. Repository roots and titles are left out: a link to
    a repository is not a link to one paper in it."""
    from ..citation.discover import surface_forms
    from ..paths import load_registry, publications

    forms = load_registry("citation-forms")
    table: dict[str, str] = {}
    for pub in publications():
        for form in surface_forms(pub, forms):
            if form.kind in ("blob-url", "raw-url", "pdf-url", "landing"):
                table[_url_key("https://" + form.value)] = pub["id"]
    for stub in (load_registry("work-aliases").get("stubs") or {}).values():
        for url in [stub.get("document_url"), *(stub.get("other_urls") or [])]:
            if url:
                table[_url_key(url)] = stub["id"]
    return table


def links_to_works(post: Post, forms: dict[str, str]) -> list[str]:
    return sorted({forms[key] for link in post.links if (key := _url_key(link)) in forms})


_COSAI_FILE = re.compile(r"^https?://(?:www\.)?(?:github\.com/cosai-oasis/[^/]+/(?:blob|raw)/"
                         r"|coalitionforsecureai\.org/wp-content/uploads/.+\.pdf"
                         r"|secureaistg\.wpenginepowered\.com/wp-content/uploads/.+\.pdf)",
                         re.I)


def unregistered_cosai_files(post: Post, forms: dict[str, str]) -> list[str]:
    """The subset of unmatched paper-like links that CoSAI hosts. A PDF on another site
    is somebody else's document, and no evidence of a CoSAI work."""
    return [link for link in unmatched_paper_links(post, forms) if _COSAI_FILE.match(link)]


def unmatched_paper_links(post: Post, forms: dict[str, str]) -> list[str]:
    """Links that look like a paper but match no registered form: a CoSAI repository
    file, or a PDF. Reported for curation, never guessed into a link."""
    out, seen = [], set()
    for link in post.links:
        key = _url_key(link)                 # one entry per file, not per #fragment
        if key in forms or key in seen:
            continue
        seen.add(key)
        if re.search(r"github\.com/cosai-oasis/[^/]+/(?:blob|raw)/", link) or \
                re.search(r"\.pdf(?:$|[?#])", link, re.I):
            out.append(link)
    return out


# --- the graph ---------------------------------------------------------------------------

def existing_instants() -> frozenset[str]:
    """Days another graph already declares, to be referenced here, never re-declared:
    one triple in two named graphs doubles every row joined through it."""
    from ..paths import CATALOG_TTL

    owned = Graph()
    for path in (CATALOG_TTL, ONTOLOGY / "citations.ttl", ONTOLOGY / "maillist.ttl"):
        if path.exists():
            owned.parse(path, format="turtle")
    return frozenset(str(value) for value in owned.objects(None, COSAIC.date))


def build(feed: Feed, forms: dict[str, str] | None = None,
          owned_instants: frozenset[str] = frozenset()) -> Graph:
    forms = forms if forms is not None else {}
    g = Graph()
    g.bind("cosaic", COSAIC)
    g.bind("obo", OBO)
    declared: set[str] = set()

    def instant(day: str) -> URIRef:
        node = COSAIC[f"instant-{day}"]
        if day not in declared and day not in owned_instants:
            declared.add(day)
            g.add((node, RDF.type, COSAIC.Instant))
            g.add((node, COSAIC.date, Literal(day, datatype=XSD.date)))
        return node

    feed_url = Literal(FEED_URL, datatype=XSD.anyURI)
    for post in feed.posts:
        node = COSAIC[f"post-{post.post_id}"]
        g.add((node, RDF.type, COSAIC.WebsitePost))
        for category in post.categories:
            if cls := CATEGORY_CLASS.get(category):
                g.add((node, RDF.type, cls))
            g.add((node, COSAIC.siteCategory, Literal(category)))
        g.add((node, RDFS.label, Literal(post.title, lang="en")))
        g.add((node, COSAIC.sourcePostId, Literal(post.post_id)))
        g.add((node, COSAIC.sourceUrl, Literal(post.url, datatype=XSD.anyURI)))
        g.add((node, COSAIC.sourceFeed, feed_url))
        g.add((node, COSAIC.publishedAt,
               Literal(post.published_at.isoformat(), datatype=XSD.dateTime)))
        event = COSAIC[f"postevent-{post.post_id}"]
        g.add((event, RDF.type, COSAIC.PublicationEvent))
        g.add((event, RDFS.label, Literal(f"posting of {post.title}", lang="en")))
        g.add((event, HAS_PARTICIPANT, node))
        g.add((event, OCCUPIES_TEMPORAL_REGION,
               instant(post.published_at.date().isoformat())))
        for work in links_to_works(post, forms):
            g.add((node, COSAIC.linksTo, COSAIC[f"pub-{work}"]))
        for link in unregistered_cosai_files(post, forms):
            g.add((node, COSAIC.linksToUnregistered,
                   Literal(link.split("#", 1)[0], datatype=XSD.anyURI)))

    if feed.posts:
        window = COSAIC["coverage-feed-coalitionforsecureai"]
        g.add((window, RDF.type, COSAIC.CoverageWindow))
        g.add((window, RDF.type, COSAIC.FeedCoverageWindow))
        first, last = feed.posts[0].published_at.date(), feed.posts[-1].published_at.date()
        g.add((window, RDFS.label,
               Literal(f"{SITE_HOST} feed: {first}..{last}, fetched {feed.fetched_on}",
                       lang="en")))
        g.add((window, COSAIC.sourceFeed, feed_url))
        g.add((window, COSAIC.earliestItem, Literal(first.isoformat(), datatype=XSD.date)))
        g.add((window, COSAIC.latestItem, Literal(last.isoformat(), datatype=XSD.date)))
        g.add((window, COSAIC.fetchedOn, Literal(feed.fetched_on, datatype=XSD.date)))
        g.add((window, COSAIC.boundsKnown, Literal(False)))
    return g


# --- the report --------------------------------------------------------------------------

def write_report(feed: Feed, forms: dict[str, str]) -> str:
    """Titles, dates, categories and links only; the feed is public, but post bodies
    are not copied."""
    blogs = [p for p in feed.posts if "Blog Post" in p.categories]
    linked = [p for p in feed.posts if links_to_works(p, forms)]
    lines = [
        "# Website -- the coalitionforsecureai.org feed",
        "",
        f"- feed: `{FEED_URL}`, fetched **{feed.fetched_on}**",
        f"- posts: **{len(feed.posts)}** ({len(blogs)} in \"Blog Post\"), "
        f"{feed.posts[0].published_at.date() if feed.posts else '—'} to "
        f"{feed.posts[-1].published_at.date() if feed.posts else '—'}",
        f"- posts linking to a registered CoSAI work: **{len(linked)}**",
        f"- items refused as not on {SITE_HOST}: **{len(feed.refused)}**",
        "",
        "No authorship is recorded: the feed names only the posting account.",
        "",
        "## Posts",
        "",
        "| published (UTC) | post | categories | links to |",
        "| --- | --- | --- | --- |",
    ]
    for post in reversed(feed.posts):
        works = ", ".join(f"`{w}`" for w in links_to_works(post, forms)) or "—"
        title = post.title.replace("|", "\\|")
        lines.append(f"| {post.published_at:%Y-%m-%d %H:%M} | [{title}]({post.url}) "
                     f"| {', '.join(post.categories)} | {works} |")
    unmatched = [(p, unmatched_paper_links(p, forms)) for p in feed.posts]
    unmatched = [(p, links) for p, links in unmatched if links]
    lines += ["", "## Paper-like links matching no registered work", "",
              "A CoSAI repository file or a PDF the post links to that no publication's",
              "URL forms cover. Add the form to registry/citation-forms.yaml if it is one.",
              ""]
    for post, links in reversed(unmatched):
        lines.append(f"- {post.published_at:%Y-%m-%d} {post.title}")
        lines += [f"  - {link}" for link in links]
    if not unmatched:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--refresh", action="store_true",
                        help="fetch the feed again before building")
    parser.add_argument("--no-store", action="store_true",
                        help="write website.ttl only, skip reloading the store")
    args = parser.parse_args(argv)

    if args.refresh or not (CACHE / "manifest.json").exists():
        fetch()
    feed = load_cache()
    forms = work_url_forms()
    graph = build(feed, forms, existing_instants())
    WEBSITE_TTL.write_text(
        "# GENERATED by `python -m bubo_graphrag.ingest.website` -- do not hand-edit.\n"
        f"# From {FEED_URL}, fetched {feed.fetched_on}. Credits no author.\n\n"
        + graph.serialize(format="turtle"), encoding="utf-8")
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "website.md").write_text(write_report(feed, forms), encoding="utf-8")
    print(f"{len(feed.posts)} posts, fetched {feed.fetched_on} -> {len(graph)} triples")
    print(f"  {WEBSITE_TTL}")
    print(f"  {REPORTS / 'website.md'}")
    if feed.refused:
        print(f"  refused {len(feed.refused)} items not on {SITE_HOST}", file=sys.stderr)
    if not args.no_store:
        from ..store import load_store
        print(f"  store reloaded: {load_store()} quads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
