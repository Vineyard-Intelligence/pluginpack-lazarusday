# pluginpack-lazarusday

Reads [lazarus.day](https://lazarus.day/iocs/)'s public DPRK indicator index into a Vineyard graph:
a **keyword search** over the index, and an **exact-record lookup** for indicators already on the
canvas.

Two plugins:

- **Lazarus Day IOC Search** (`run.vineyard.plugins.lazarusday_search`) — takes a keyword (and an
  optional category and page count), searches `https://lazarus.day/iocs/?q=…`, and stages each
  match as the node its category names, carrying the record URL and the site's first/last-seen
  dates.
- **Lazarus Day IOC Lookup** (`run.vineyard.plugins.lazarusday_lookup`) — takes selected Domain,
  IP Address, URL, File Hash, E-mail Address, Crypto Address or ASN nodes, fetches each one's
  exact record page, writes the record's dates and detail onto the node, adds each report that names
  it as a Campaign linked `reported in`, and optionally adds the related IPs and URLs the site lists
  for a Domain or ASN.

Desktop only. lazarus.day sends no `Access-Control-Allow-Origin`, so the browser build cannot read
its HTML; both plugins use the desktop shell's anonymous probe (`web_probe`) and say so instead of
failing with a CORS error in the web build.

## What the source actually is

Measured 2026-10-22, so the numbers are a snapshot rather than a promise:

| Fact | Value |
| --- | --- |
| Indicators | 32,656 |
| Categories | `ipv4`, `hash`, `domain`, `url`, `email`, `wallet`, `asn`, and `yara` (browsable, but `?q=` never matches YARA names) |
| Search | `?q=` — case-insensitive **substring of the indicator value only** |
| Ordering | Newest first (`date_desc`) |
| Page size | 15; `?page=N`, and a page past the end answers **404** |
| Record page | `/iocs/<value>/` — exact lookup, 404 when unlisted |
| API | None found. The only JSON is the per-entity `/json/network/` graph data, whose names are truncated to 30 characters |
| CORS | None |
| robots.txt | `Disallow: /manager/`, `/admin/`, `/api/`; `/iocs` is allowed |
| Every page carries | “These IoCs were automatically extracted using regular expressions or an LLM and may include non-malicious data.” |

Three consequences shaped the code:

1. **The list view is the section to parse.** The page renders the same fifteen rows three times
   (table, list, grid). The table truncates every value to 30 characters with a literal `…`; the
   list view is the same data untruncated, and grid view is cut off at the parser so a future change
   there cannot double every row.
2. **Values are read from the href, not the anchor text.** E-mails are Cloudflare-obfuscated in the
   text (`[email protected]`), and the site encodes the value **twice** in the path. Both quirks
   are why `parseSearchPage` decodes the `href` twice and why `iocPath()` encodes twice; a
   singly-encoded path answers 404 (verified, not inferred).
3. **A 404 is an answer.** For the lookup it means “the site does not list this value” — a real
   negative. For page 2+ of a search it means “past the last page”. Neither is counted as a failed
   request, which is the difference between a clean result and a silently incomplete one.

## Search: keyword → indicator nodes

`?q=` matches a substring of the stored value. It does **not** search report titles, actors or
tags: `q=Kimsuky` returns one indicator (a value containing “kimsuky”), not the site's hundreds of
reports that mention Kimsuky. So this plugin is a way to discover indicators, and the Lookup plugin is the way to get reporting for
a known one.

Each result becomes the concrete node its category names:

| Site category | Node type | Notes |
| --- | --- | --- |
| Domain | `infrastructure.domain` | lower-cased |
| IPv4 / IPv6 | `infrastructure.ip_address` | `version` set |
| URL | `web.url` | trailing slash preserved |
| E-mail | `identity.email_address` | recovered from the href |
| Wallet | `financial.crypto_address` | chain is not stated by the site, so `currency` is left empty |
| ASN | `infrastructure.autonomous_system` | `AS149440` → `149440` |
| Hash (SHA-256) | `threat.file_hash` | |
| Hash (MD5 / SHA-1) | `threat.indicator` | `file_hash` requires `sha256`, so a shorter digest has no legal `file_hash` node |

Every node carries `lazarus_day_url` and, when the row has them, `lazarus_day_first_seen` /
`lazarus_day_last_seen`.

**No anchor node is invented for the query.** A search is not an entity; a Campaign named after
“blockchain” would be a fabricated thing that every later search would merge into. The results stand
as themselves, which is also how the Shodan Search plugin ships. Nodes that already exist on the
canvas are reused by the host's normal identity de-duplication.

Params: `query` (required), `category` (one of the seven or `all`), `pages` (1–10, default 1;
15 indicators each). The run states the total match count and how many pages of it were read.

## Lookup: exact record → metadata, reports, pivots

There is no search in this path. `/iocs/<value>/` is an exact record lookup, so one request per
node and no risk of matching `11.2.3.45` for a selected `1.2.3.4`. A File Hash tries its digests
strongest-first (`sha256` → `sha1` → `md5`) because the site may index any one of them.

What is written:

| Source fact | Where it goes |
| --- | --- |
| First/last seen | `lazarus_day_first_seen` / `lazarus_day_last_seen` |
| IP country, coordinates, ASN operator | `lazarus_day_country`, `lazarus_day_location`, `lazarus_day_asn_name`; `asn` (declared integer) |
| IP's ASN | an `infrastructure.autonomous_system` node + `announced by` |
| MD5 / SHA-1 on a hash record | `md5` / `sha1` on the File Hash node |
| ASN page's operator | `autonomous_system_name` on the ASN node |
| Each related report | a `threat.campaign` node + `reported in`; the record URL, author, date and tags are kept |
| Domain's resolved IPs / URLs, ASN's associated IPs | `infrastructure.ip_address` / `web.url` nodes + `resolves to`, `hosts`, `announces` |

The report → Campaign mapping is this pack's model, borrowed from the OTX pack: a report is not
literally a campaign, but Campaign is the typepack's node for “a coordinated set of malicious
activities” with a name, a date and a description, and it is where analysts put reporting. The
report's own URL stays on the node (`lazarus_day_url`) and the edge carries `report_date` and
`author`, so the claim is traceable to the page.

**Actors are deliberately not inferred from tags.** The site's tags mix actor names, malware
families and generic terms (`#NPM`, `#PyPI`, `#MoonstoneSleet`). Turning every tag into a Threat
Actor node would be a guess dressed as a finding.

Params: `include_related_iocs` (default on) and `max_related_iocs` (default 50, max 200). An ASN
page can list over a hundred addresses; the run says how many were left out.

## Limits, stated rather than hidden

- **YARA is out of scope for now.** The site has a browsable YARA category, but its `?q=` search
  never matches YARA rule names — `q=lazarus_relayshell&category=yara` returns 0 — and this pack
  does not assume a YARA typepack is installed. It therefore does not offer the category, and it
  skips (and counts) a YARA row if one ever does appear in a result page. YARA rules are still
  browsable on the site itself.
- **The source warns about its own data.** Every page says its IoCs are regex/LLM-extracted and may
  include non-malicious values. Both plugins repeat that in the run summary. A hit means “appears in
  DPRK reporting”, not “confirmed malicious”.
- **Related reports are what the page rendered.** The site shows the reports inline; the run counts
  what it saw and compares it to the page's own counter, and caps staging at 50 per run.
- **A bot challenge is not an empty result.** A 403/503, or a real challenge body, is counted as
  `blocked` and named in the summary; a truncated page is a failure, not a short page. Cloudflare's
  ordinary bot-detection script (`challenge-platform`) is injected into every page including 404s,
  so it is deliberately *not* a challenge marker — matching it turned “not listed” into “blocked”
  during development.
- **Politeness.** Requests are paced at 350 ms; a 429 or 5xx gets one retry (honouring
  `Retry-After` when present). No credential is sent; the probe is anonymous and does not follow
  redirects, so this pack follows them itself (up to 4).

## Checks

```
npm install
npm run build       # bundle + manifest + parser selftest + functional tests
npm run typecheck
npm run live        # reads the live site; not part of build
```

- `src/selftest.ts` — parsers against real bytes in `test-fixtures/` (search page, empty search,
  domain/IP/hash/ASN/e-mail/URL records, the live 404 page), plus node mapping, lookup targets,
  double-encoding and challenge detection.
- `test-plugin.mjs` — the `run()` bodies with a mocked probe and graph: what is requested, what is
  written, and what the summary says for a negative, a challenge, a redirect and a digest fallback.
- `live-check.mjs` — the same bundle against the real site, with a memory graph; asserts shape, not
  specific indicators.

## Data and licence

Pack code: Apache-2.0 (see `LICENSE`). The indicator data belongs to
[lazarus.day](https://lazarus.day/about/); this pack reads it anonymously and read-only, and links
every staged node back to its record page. Not affiliated with the site.

Published in the Vineyard registry as `run.vineyard.pluginpacks.lazarusday`, pinned to the
manifest commit in
[`packs/run.vineyard.pluginpacks.lazarusday.json`](https://github.com/Vineyard-Intelligence/registry/blob/main/packs/run.vineyard.pluginpacks.lazarusday.json).
