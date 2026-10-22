# pluginpack-lazarusday

Searches and reads the public DPRK indicator index at **https://lazarus.day** into a Vineyard
graph: a keyword search over the index, and an exact-record lookup for indicators already on the
canvas.

Data source: [lazarus.day](https://lazarus.day), maintained by
[@lazarusholic](https://x.com/lazarusholic). The pack declares one network endpoint,
`https://lazarus.day/iocs`, and reads the public pages anonymously. Every request — including each
page of a paginated search — carries `utm_source=vineyard` so the site's logs can see where the
traffic came from; the record URLs stored on graph nodes are kept clean. Desktop only: the site sends
no CORS headers, and the desktop shell waives cross-origin protection for the endpoint a pack
declares.

## Plugins

- **lazarus.day IOC Search** (`run.vineyard.plugins.lazarusday_search`) — keyword → indicator nodes.
  Params: `query` (required), `category` (one of seven; default `all`), `pages` (1–10, default 1).
- **lazarus.day IOC Lookup** (`run.vineyard.plugins.lazarusday_lookup`) — selected indicators → their
  records, related reports as Campaigns, and optionally related IOCs. Params:
  `include_related_iocs` (default on), `max_related_iocs` (default 50, max 200).

## Search

`?q=` is a case-insensitive substring match on the indicator value — 15 results per page, newest
first. Results become Domain, IP Address, URL, File Hash, E-mail Address, Crypto Address, ASN or
Indicator nodes, each carrying `lazarus_day_url` and the site's first/last-seen dates.

Hash results are resolved through their record page, so a File Hash carries the file's MD5, SHA-1
and SHA-256 together. A record with no SHA-256 stays an Indicator with its digest type. Resolution is
capped at 60 hash records per run; the rest fall back to the listed digest.

## Lookup

Each selected node is read as an exact record (`/iocs/<value>/`): its dates and detail are written
onto the node, and every report that names it becomes a Campaign linked `reported in`, with the
report URL, author, date and tags kept. A Domain or ASN can also add the IPs and URLs the site lists
for it. A 404 means the site does not list the value — not a failed lookup.

## Notes

- lazarus.day flags its IoCs as automatically extracted and warns they may include non-malicious
  data. A hit means “appears in DPRK reporting”, not a confirmed verdict.
- YARA rules are not staged: the site's `?q=` does not match YARA names, and no YARA typepack is
  assumed.
- Requests are paced at 350 ms; a 429 or 5xx gets one retry.
- Report → Campaign is this pack's model; tags do not become Threat Actors.

## Build

```sh
npm install
npm run build   # bundle + manifest + parser selftest + functional tests
npm run live    # reads the live site; not part of build
```

## Licence

Pack code: Apache-2.0 (see `LICENSE`). The site's content and IoC data are
© 2021–2026 [@lazarusholic](https://x.com/lazarusholic), licensed
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/); this pack reads them at runtime and
links every node to its source page. `test-fixtures/` contains trimmed copies of that content for
parser tests and remains under CC BY-SA 4.0 (see `NOTICE`). Not affiliated with the site.

Published in the Vineyard registry as `run.vineyard.pluginpacks.lazarusday`
([entry](https://github.com/Vineyard-Intelligence/registry/blob/main/packs/run.vineyard.pluginpacks.lazarusday.json)).
