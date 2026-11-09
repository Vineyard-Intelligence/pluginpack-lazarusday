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
    'For checking whether an indicator appears in public reporting on North Korean (DPRK) threat activity and which reports name it, or finding indicators in that reporting by part of their value. Search matches the indicator value only, not report titles or actor names.',
    '',
    "**Needs:** no API key or account; the site's public pages are read anonymously.",
    '',
    "**Cost:** no published quota; the site is one researcher's public dataset, not an API, so requests are spaced 350 ms apart.",
    '',
    '**Who sees it:** only lazarus.day, which receives the search keywords and the indicator values looked up. The indicators themselves are never contacted.',
    '',
    '**Read results with care:**',
    '- lazarus.day flags its IoCs as automatically extracted and warns that they may include non-malicious data. A hit means the value appears in DPRK reporting, not a confirmed verdict.',
    '- A lookup with no record is a real negative: the site does not list the value. A bot challenge or a rate limit is reported as such, never as "no results".',
    '- A report is modelled as a Campaign; its tags stay text and never become Threat Actor nodes.',
    '',
    "**Data and licences:** the site's content and IoC data are © 2021–2026 @lazarusholic, CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/). The pack is not affiliated with the site.",
    '',
    "**Source:** https://github.com/Vineyard-Intelligence/pluginpack-lazarusday (Apache-2.0; the site captures in `test-fixtures/` and the card thumbnail, cropped from the site's artwork, stay CC BY-SA 4.0, see `NOTICE`)",
].join('\n');

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.lazarusday',
    content_type: 'vineyard:pluginpack',
    name: 'lazarus.day',
    version: '1.5.1',
    summary:
        'Searches and reads lazarus.day (https://lazarus.day), the public DPRK indicator index by @lazarusholic (https://x.com/lazarusholic): keyword search stages matches as graph nodes, and exact-record lookup adds the reports naming them. Desktop only.',
    description: PACK_PAGE,
    thumbnail_url: 'assets/thumbnail.png',
    plugins: [lazarusSearch, lazarusLookup],
});
