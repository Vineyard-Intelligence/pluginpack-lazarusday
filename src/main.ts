// The Lazarus Day pack — two views of one public dataset.
//
// Search answers "what does this site know about <keyword>"; Lookup answers "what does this site
// know about <this exact indicator>". They share the parsers and the probe wrapper, and nothing
// else: a search stages indicators it found, a lookup enriches what the analyst already selected.
// Both are desktop-only for the same reason — lazarus.day serves no CORS headers — and both say so
// at the point of use rather than failing with an opaque browser error.
import { definePluginPack } from './sdk';
import { lazarusLookup } from './lookup';
import { lazarusSearch } from './search';

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.lazarusday',
    content_type: 'vineyard:pluginpack',
    name: 'Lazarus Day',
    version: '1.0.0',
    description:
        'Searches and reads the lazarus.day DPRK indicator index: a keyword search that stages indicators as graph nodes, and an exact-record lookup that adds the reports naming a selected indicator. Desktop only.',
    plugins: [lazarusSearch, lazarusLookup],
});
