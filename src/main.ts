// The lazarus.day pack — two views of one public dataset (https://lazarus.day/iocs/).
//
// Search answers "what does this site know about <keyword>"; Lookup answers "what does this site
// know about <this exact indicator>". They share the parsers and the declared-endpoint fetch
// wrapper, and nothing else: a search stages indicators it found, a lookup enriches what the
// analyst already selected. Both declare exactly ONE network endpoint — https://lazarus.day/iocs —
// and both are desktop-only: the site sends no CORS headers, and it is the desktop shell that
// waives cross-origin protection for an installed pack's declared origin.
import { definePluginPack } from './sdk';
import { lazarusLookup } from './lookup';
import { lazarusSearch } from './search';

// The pack's page in the marketplace drawer, in Markdown. `summary` is the card's one line and must
// equal the registry entry's. Images are never loaded and links are shown, not followed, so sources
// are named by plain URL.
const PACK_PAGE = [
    'Brings lazarus.day, the public index of indicators from reporting on North Korean (DPRK) threat activity maintained by @lazarusholic, into the graph. One plugin searches the index by keyword and stages what it finds; the other reads the exact record of indicators already on the canvas, including the reports that name them.',
    '',
    '## Plugins',
    '',
    '### lazarus.day IoC Search',
    '',
    '- **Runs on:** no selection; it takes a keyword.',
    '- **Parameters:** `query` (required); `category`, one of `all` (default), `domain`, `ipv4`, `url`, `hash`, `email`, `wallet`, `asn`; `pages`, 1 to 10 result pages (default 1).',
    "- **Adds:** one node per result, of the type its category names: Domain, IP Address, URL, File Hash, E-mail Address, Crypto Address, Autonomous System, or Indicator. Each carries its record page in `lazarus_day_url` and the site's first- and last-seen dates (`lazarus_day_first_seen`, `lazarus_day_last_seen`). No node is made for the query itself, and no edges.",
    "- **Matching:** the site's search is a case-insensitive substring match on the indicator value only, not on report titles or actor names. 15 results per page, newest first.",
    "- **Hashes:** each hash result is resolved through its record page, so a File Hash node carries the file's MD5, SHA-1 and SHA-256 together. A record with no SHA-256 is staged as an Indicator with its digest type. At most 60 hash records are resolved per run; past that, or after a failed record fetch, the listed digest is used as it is.",
    "- **YARA:** the site's YARA category is not staged. YARA rows reached through `all` are skipped and counted in the run summary.",
    '',
    '### lazarus.day IoC Lookup',
    '',
    '- **Runs on:** selected Domain, IP Address, URL, File Hash, E-mail Address, Crypto Address and Autonomous System nodes. A File Hash is tried by SHA-256, then SHA-1, then MD5.',
    '- **Parameters:** `include_related_iocs` (default on); `max_related_iocs`, the most related IoCs added per selected Domain or ASN (default 50, maximum 200).',
    '- **Adds:**',
    '  - onto the selected node: `lazarus_day_url` and the first- and last-seen dates; for an IP Address also `asn`, `lazarus_day_asn_name`, `lazarus_day_country` and `lazarus_day_location`; for a File Hash the `md5` and `sha1` the record lists; for an Autonomous System its `autonomous_system_name`;',
    '  - for an IP Address whose record names an ASN, an Autonomous System node linked `announced by`;',
    '  - each report that names the indicator, as a Campaign node (title, author, date, tags, report URL) linked `reported in`, at most 50 reports per run;',
    '  - with related IoCs on: for a Domain, the IPs it resolved to (`resolves to`) and the URLs on it (`hosts`); for an Autonomous System, its associated IPs (`announces`).',
    '- **Notes:** each lookup reads one exact record (`/iocs/<value>/`), not a search, so a 404 means the site does not list the value: a real negative, not a failed lookup.',
    '',
    '## Requirements',
    '',
    '- **Desktop only.** lazarus.day sends no CORS headers, and the Vineyard desktop app waives cross-origin protection only for the endpoint an installed pack declares. In the web app both plugins stop with a message instead of returning an empty result.',
    "- No API key or account: the site's public pages are read anonymously.",
    '',
    '## Cost and limits',
    '',
    'The site is one researcher\'s public dataset, not an API with a published quota. The pack spaces its requests 350 ms apart and retries once after a 429 or a 5xx. A bot challenge or a rate limit is reported as such, never as "no results".',
    '',
    '## What it contacts',
    '',
    'Only lazarus.day, and only under the one endpoint the pack declares, `https://lazarus.day/iocs`; the host refuses any other request. The site receives the search keywords and the indicator values looked up. Requests carry no credentials. The indicators themselves are never contacted.',
    '',
    '## Data and licences',
    '',
    "- The site's content and IoC data are © 2021–2026 @lazarusholic (https://x.com/lazarusholic), licensed CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/). The pack reads them at runtime; search results, looked-up nodes, related IoCs and report Campaigns carry their lazarus.day page in `lazarus_day_url`.",
    '- lazarus.day flags its IoCs as automatically extracted and warns that they may include non-malicious data. A hit means the value appears in DPRK reporting, not a confirmed verdict.',
    "- A report becomes a Campaign because that is this pack's model. Report tags are kept as text and do not become Threat Actor nodes.",
    "- The pack's card thumbnail is a resized crop of the site's artwork, also under CC BY-SA 4.0.",
    '- The pack is not affiliated with the site.',
    '',
    '## Source',
    '',
    'https://github.com/Vineyard-Intelligence/pluginpack-lazarusday (Apache-2.0; the trimmed site pages in `test-fixtures/` and the thumbnail remain CC BY-SA 4.0, see `NOTICE`). `dist/pack.mjs` and the manifest are built from `src/` with a pinned esbuild (`node build.mjs`), so the published bundle can be checked against the source.',
].join('\n');

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.lazarusday',
    content_type: 'vineyard:pluginpack',
    name: 'lazarus.day',
    version: '1.5.0',
    summary:
        'Searches and reads lazarus.day (https://lazarus.day), the public DPRK indicator index by @lazarusholic (https://x.com/lazarusholic): keyword search stages matches as graph nodes, and exact-record lookup adds the reports naming them. Desktop only.',
    description: PACK_PAGE,
    thumbnail_url: 'assets/thumbnail.png',
    plugins: [lazarusSearch, lazarusLookup],
});
