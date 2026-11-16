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
    'For checking whether an indicator appears in public reporting on North Korean (DPRK) activity and which reports name it, or for finding indicators there by part of their value (not by report title or actor name).',
    '',
    "**Needs:** nothing; the public pages are read anonymously.",
    '',
    "**Cost:** none published; the site is one researcher's dataset, not an API, so requests are 350 ms apart.",
    '',
    '**Who sees it:** only lazarus.day, which receives each keyword and indicator looked up. The indicators are never contacted.',
    '',
    '**Read results with care:**',
    '- lazarus.day flags its IoCs as auto-extracted and possibly benign: a hit means the value appears in DPRK reporting, not a verdict.',
    '- No record is a real negative; a bot challenge or rate limit is reported as such, never as "no results".',
    '- A report is a Campaign; its tags stay text and never become Threat Actor nodes.',
    "- The site does not say which chain a wallet is on, so an address gets a network only when its format settles one (bc1…, ltc1…, T…, a CashAddr). A 0x address is on an unstated EVM chain; 1… or 3… stays unknown (Bitcoin, Bitcoin Cash or SV).",
    '',
    "**Data and licences:** the site's content and IoC data are © 2021–2026 @lazarusholic, CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/). The pack is not affiliated with the site.",
    '',
    "**Source:** https://github.com/Vineyard-Intelligence/pluginpack-lazarusday (Apache-2.0; the site captures in `test-fixtures/` and the thumbnail cropped from the site's artwork stay CC BY-SA 4.0, see `NOTICE`)",
].join('\n');

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.lazarusday',
    content_type: 'vineyard:pluginpack',
    name: 'lazarus.day',
    version: '1.7.0',
    summary:
        'Searches and reads lazarus.day (https://lazarus.day), the public DPRK indicator index by @lazarusholic (https://x.com/lazarusholic): keyword search stages matches as graph nodes, and exact-record lookup adds the reports naming them. Desktop only.',
    description: PACK_PAGE,
    thumbnail_url: 'assets/thumbnail.png',
    plugins: [lazarusSearch, lazarusLookup],
});
