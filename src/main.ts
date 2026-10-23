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

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.lazarusday',
    content_type: 'vineyard:pluginpack',
    name: 'lazarus.day',
    version: '1.4.0',
    description:
        'Searches and reads lazarus.day (https://lazarus.day), the public DPRK indicator index by @lazarusholic (https://x.com/lazarusholic): keyword search stages matches as graph nodes, and exact-record lookup adds the reports naming them. Desktop only.',
    thumbnail_url: 'assets/thumbnail.png',
    plugins: [lazarusSearch, lazarusLookup],
});
