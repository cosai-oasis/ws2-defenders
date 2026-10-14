"""Website feed ingest tests.

Fixtures are synthetic feed pages written inline; no test fetches the site. The rules
under test are the ones the graph promises: one site only, no authorship, links only by
registered URL forms, dates owned by one graph, and an honest coverage window.
"""

from __future__ import annotations

import datetime as dt

import pytest
from rdflib import Literal, Namespace, RDF, XSD

from bubo_graphrag.ingest import website as W

COSAIC = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")
POSTER = "Casey Poster-Account"


def item(post_id: str, title: str, date: str, categories=("Blog Post",),
         link: str | None = None, body: str = "<p>text</p>") -> str:
    link = link or f"https://www.coalitionforsecureai.org/{title.lower().replace(' ', '-')}/"
    cats = "".join(f"<category><![CDATA[{c}]]></category>" for c in categories)
    return f"""<item>
      <title>{title}</title>
      <link>{link}</link>
      <dc:creator><![CDATA[{POSTER}]]></dc:creator>
      <pubDate>{date}</pubDate>
      {cats}
      <guid isPermaLink="false">https://secureaistg.wpenginepowered.com/?p={post_id}</guid>
      <content:encoded><![CDATA[{body}]]></content:encoded>
    </item>"""


def page(*items: str) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"
     xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel><title>Coalition for Secure AI</title>{''.join(items)}</channel>
</rss>""".encode()


MCP_BLOB = ("https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/"
            "whitepapers/model-context-protocol-security.md")
FORMS = {W._url_key(MCP_BLOB): "model-context-protocol-security"}


def feed(*items: str, fetched_on: str = "2026-09-26") -> W.Feed:
    return W.parse_pages([page(*items)], fetched_on)


# --- one site, no authorship ----------------------------------------------------------

def test_the_posting_account_never_reaches_the_graph():
    """dc:creator names who posted, not who wrote; no rule credits a post's author."""
    graph = W.build(feed(item("10", "A Post", "Mon, 21 Sep 2026 10:00:00 +0000")))
    assert POSTER not in graph.serialize(format="turtle")
    assert not list(graph.subjects(RDF.type, COSAIC.Person))
    assert not any("Role" in str(o) for o in graph.objects(None, RDF.type))


def test_an_item_off_the_site_is_refused():
    result = feed(item("11", "Elsewhere", "Mon, 21 Sep 2026 10:00:00 +0000",
                       link="https://blog.example.com/elsewhere/"))
    assert result.posts == [] and result.refused == ["https://blog.example.com/elsewhere/"]


def test_the_post_id_comes_from_the_guid_but_not_its_staging_host():
    graph = W.build(feed(item("1786", "A Post", "Mon, 21 Sep 2026 10:00:00 +0000")))
    post = COSAIC["post-1786"]
    assert graph.value(post, COSAIC.sourcePostId) == Literal("1786")
    assert "wpenginepowered" not in graph.serialize(format="turtle")


def test_a_redirect_off_the_site_is_refused(monkeypatch, tmp_path):
    class Response:
        def geturl(self):
            return "https://elsewhere.example.com/feed/"

        def read(self):
            return page()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(W.urllib.request, "urlopen", lambda *a, **k: Response())
    with pytest.raises(RuntimeError, match="redirected off the site"):
        W.fetch(tmp_path)


# --- what a post records -----------------------------------------------------------------

def test_site_categories_type_the_post_and_are_kept_verbatim():
    graph = W.build(feed(
        item("1", "Blog", "Mon, 21 Sep 2026 10:00:00 +0000", ("Blog Post", "WS4")),
        item("2", "Release", "Tue, 22 Sep 2026 10:00:00 +0000", ("Press Release",)),
        item("3", "Event", "Wed, 23 Sep 2026 10:00:00 +0000", ("Events",)),
    ))
    types = {str(p).rsplit("-", 1)[1]: {str(t).rsplit("#", 1)[1]
                                        for t in graph.objects(p, RDF.type)}
             for p in graph.subjects(COSAIC.sourcePostId, None)}
    assert types == {"1": {"WebsitePost", "BlogPost"}, "2": {"WebsitePost", "PressRelease"},
                     "3": {"WebsitePost"}}
    assert set(graph.objects(COSAIC["post-1"], COSAIC.siteCategory)) == \
        {Literal("Blog Post"), Literal("WS4")}


def test_the_publication_time_is_exact_and_in_utc():
    graph = W.build(feed(item("5", "A Post", "Mon, 21 Sep 2026 10:00:00 -0400")))
    assert graph.value(COSAIC["post-5"], COSAIC.publishedAt) == \
        Literal("2026-09-21T14:00:00+00:00", datatype=XSD.dateTime)


def test_an_item_repeated_across_pages_is_one_post():
    one = item("7", "A Post", "Mon, 21 Sep 2026 10:00:00 +0000")
    result = W.parse_pages([page(one), page(one)], "2026-09-26")
    assert [p.post_id for p in result.posts] == ["7"]


# --- links to works ----------------------------------------------------------------------

@pytest.mark.parametrize("href", [
    MCP_BLOB,
    MCP_BLOB + "#section-3",
    MCP_BLOB.replace("https://", "http://www."),
    MCP_BLOB + "/",
])
def test_a_link_matches_a_registered_form_however_it_is_written(href):
    body = f'<a href="{href}">the paper</a>'
    graph = W.build(feed(item("8", "A Post", "Mon, 21 Sep 2026 10:00:00 +0000", body=body)),
                    FORMS)
    assert graph.value(COSAIC["post-8"], COSAIC.linksTo) == \
        COSAIC["pub-model-context-protocol-security"]


def test_a_repository_link_is_not_a_link_to_a_paper():
    body = '<a href="https://github.com/cosai-oasis/ws4-secure-design-agentic-systems">repo</a>'
    graph = W.build(feed(item("9", "A Post", "Mon, 21 Sep 2026 10:00:00 +0000", body=body)),
                    FORMS)
    assert graph.value(COSAIC["post-9"], COSAIC.linksTo) is None


def test_an_unregistered_pdf_is_reported_once_not_linked():
    pdf = "https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/paper.pdf"
    body = f'<a href="{pdf}">pdf</a> <a href="{pdf}#page=2">again</a>'
    post = feed(item("12", "A Post", "Mon, 21 Sep 2026 10:00:00 +0000", body=body)).posts[0]
    assert W.links_to_works(post, FORMS) == []
    assert W.unmatched_paper_links(post, FORMS) == [pdf]


# --- dates and coverage ------------------------------------------------------------------

def test_a_day_another_graph_owns_is_referenced_not_redeclared():
    graph = W.build(feed(item("13", "A Post", "Mon, 21 Sep 2026 10:00:00 +0000")),
                    owned_instants=frozenset({"2026-09-21"}))
    day = COSAIC["instant-2026-09-21"]
    assert (None, None, day) in graph
    assert (day, RDF.type, COSAIC.Instant) not in graph


def test_the_window_records_its_items_and_its_fetch_and_never_known_bounds():
    graph = W.build(feed(item("14", "Old", "Mon, 21 Sep 2026 10:00:00 +0000"),
                         item("15", "New", "Thu, 24 Sep 2026 10:00:00 +0000"),
                         fetched_on="2026-09-26"))
    window = COSAIC["coverage-feed-coalitionforsecureai"]
    assert {COSAIC.CoverageWindow, COSAIC.FeedCoverageWindow} <= \
        set(graph.objects(window, RDF.type))
    assert graph.value(window, COSAIC.earliestItem) == Literal("2026-09-21", datatype=XSD.date)
    assert graph.value(window, COSAIC.latestItem) == Literal("2026-09-24", datatype=XSD.date)
    assert graph.value(window, COSAIC.fetchedOn) == Literal("2026-09-26", datatype=XSD.date)
    assert graph.value(window, COSAIC.boundsKnown) == Literal(False)



def test_the_registry_links_a_website_pdf_copy_to_its_work():
    """The SRF blog links only the website's PDF; that copy must resolve to the paper."""
    forms = W.work_url_forms()
    key = W._url_key("https://www.coalitionforsecureai.org/wp-content/uploads/2026/05/"
                     "CoSAI-Shared-Responsibility-Framework.pdf")
    assert forms[key] == "ai-shared-responsibility-framework"
    stub = W._url_key("https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/"
                      "the-future-of-agentic-security.pdf")
    assert forms[stub] == "future-of-agentic-security"
