// Functional test harness for dist/pack.mjs — the run() bodies, not just the parsers.
//
// The parsers are covered by src/selftest.ts. What is left is everything that needs a ctx: what
// gets requested, what gets written, and — as important — what the summary says when the answer is
// "not listed" rather than "failed". The declared endpoint is mocked with the same fixtures the parser
// test uses, so a run sees realistic bytes without touching the network.
//
// Run: node test-plugin.mjs   (npm run test:plugin)
import { readFileSync } from 'node:fs';
import pack from './dist/pack.mjs';

const fixture = (name) => readFileSync(new URL(`./test-fixtures/${name}`, import.meta.url), 'utf8');

const [search, lookup] = pack.plugins;
const ok = [];
const fail = [];
function check(name, cond) {
    (cond ? ok : fail).push(name);
}

function makeGraph(seed = {}) {
    const nodes = new Map(Object.entries(seed));
    const created = [];
    const edges = [];
    const updates = [];
    return {
        created,
        edges,
        updates,
        async get(id) {
            return nodes.get(id) ?? null;
        },
        async createNode(draft) {
            const node = { id: `n${created.length + 1}`, type: draft.type, data: { ...draft.data } };
            created.push(node);
            return node;
        },
        async updateNode(id, data) {
            updates.push({ id, data });
        },
        async createEdge(edge) {
            edges.push(edge);
        },
    };
}

function makeNet(respond) {
    const calls = [];
    return {
        calls,
        async fetch(url, init) {
            calls.push({ url, init });
            const r = respond(url) ?? { status: 404 };
            if (r.throw) throw new Error(r.throw);
            const body = r.body ?? '';
            return {
                ok: r.status >= 200 && r.status < 300,
                status: r.status,
                headers: r.headers ?? {},
                async text() {
                    return body;
                },
                async json() {
                    return JSON.parse(body);
                },
            };
        },
    };
}

function ctxOf({ net, graph, params, selection = [], platform = 'desktop' }) {
    return {
        net: net ? { fetch: net.fetch } : {},
        graph,
        run: { platform },
        input: { selection },
        params,
        config: {},
        signal: new AbortController().signal,
        progress: { set() {} },
    };
}

const RUN = (net, graph, params, selection = []) => ctxOf({ net, graph, params, selection });

function ctxOnWeb(net, graph, params, selection = []) {
    return ctxOf({ net, graph, params, selection, platform: 'web' });
}

// ================================================================ search
{
    const graph = makeGraph();
    const net = makeNet(() => ({ status: 200, body: fixture('search-blockchain.html') }));
    const r = await search.run(RUN(net, graph, { query: 'blockchain', pages: 1 }));

    check('search: one request for one page', net.calls.length === 1);
    check('search: query in the URL', net.calls[0].url.includes('q=blockchain'));
    check('search: request carries utm_source=vineyard', net.calls[0].url.includes('utm_source=vineyard'));
    check('search: no category param for "all"', !net.calls[0].url.includes('category='));
    check('search: 15 nodes staged', graph.created.length === 15);
    check(
        'search: stored provenance URLs stay clean of utm_source',
        graph.created.every((n) => !String(n.data.lazarus_day_url ?? '').includes('utm_source')),
    );
    check('search: no anchor node invented', graph.edges.length === 0);
    check(
        'search: e-mail node decoded from the Cloudflare-obfuscated href',
        graph.created.some((n) => n.type === 'identity.email_address' && n.data.email === 'blockchainjob2024@outlook.com'),
    );
    check(
        'search: domain node keeps its provenance URL',
        graph.created.some(
            (n) => n.type === 'infrastructure.domain' && n.data.lazarus_day_url === 'https://lazarus.day/iocs/dennis-blockchain.vercel.app/',
        ),
    );
    check('search: URL node preserves the trailing slash', graph.created.some((n) => n.data.url === 'https://dennis-blockchain.vercel.app/'));
    check('search: summary names the count and the total', /15 IoCs/.test(r.summary) && /27 indicators match/.test(r.summary));
    check('search: summary carries the source caveat', /automatically extracted/.test(r.summary));
    check('search: counts by kind', r.counts.domains + r.counts.emails + r.counts.urls > 0);
}
{
    // Page two is past the end: the site answers 404, which must end the paging quietly.
    const graph = makeGraph();
    const net = makeNet((url) =>
        url.includes('page=2') ? { status: 404 } : { status: 200, body: fixture('search-blockchain.html') },
    );
    const r = await search.run(RUN(net, graph, { query: 'blockchain', category: 'domain', pages: 2 }));
    check('search: page 2 requested', net.calls.length === 2 && net.calls[1].url.includes('page=2'));
    check('search: pagination carries utm_source', net.calls[1].url.includes('utm_source=vineyard'));
    check('search: category kept on every page', net.calls.every((c) => c.url.includes('category=domain')));
    check('search: past-the-end 404 is not a failure', r.counts.failed === 0 && r.counts.pages === 1);
    check('search: nodes from page 1 staged', graph.created.length === 15);
}
{
    const graph = makeGraph();
    const net = makeNet(() => ({ status: 200, body: fixture('search-empty.html') }));
    const r = await search.run(RUN(net, graph, { query: 'zzzznotfoundzzzz' }));
    check('search: empty result stages nothing', graph.created.length === 0);
    check('search: empty result is called a real negative', /lists no indicator matching/.test(r.summary));
}
{
    const graph = makeGraph();
    const net = makeNet(() => ({ status: 403, body: '<title>Just a moment...</title>' }));
    const r = await search.run(RUN(net, graph, { query: 'blockchain' }));
    check('search: challenge is counted as blocked, not as zero results', r.counts.blocked === 1 && graph.created.length === 0);
    check('search: challenge is named in the summary', /bot challenge/.test(r.summary));
}
{
    const graph = makeGraph();
    const net = makeNet(() => ({ status: 200, body: fixture('search-blockchain.html') }));
    const r = await search.run(RUN(net, graph, { query: '   ' }));
    check('search: blank query refuses before any request', net.calls.length === 0 && /Enter a search keyword/.test(r.summary));
}

{
    // YARA is out of scope for now: `all` can return YARA rows, and they must be skipped and
    // counted rather than crashing or silently disappearing.
    const yaraPage = `
<p>1 IoCs</p>
<div id="list-view" class="view-container">
<article>
    <div><hgroup><h4><a href="/iocs/lazarus_relayshell/">lazarus_relayshell</a></h4><h5>YARA</h5></hgroup></div>
    <div>First seen: 2026-01-01 • Last seen: 2026-01-02</div>
</article>
</div>
<div id="grid-view"></div>`;
    const graph = makeGraph();
    const net = makeNet(() => ({ status: 200, body: yaraPage }));
    const r = await search.run(RUN(net, graph, { query: 'relayshell' }));
    check('search: a YARA row stages nothing', graph.created.length === 0);
    check('search: a YARA row is counted, not hidden', r.counts.skipped_yara === 1);
    check('search: the skip is stated in the summary', /YARA rule result was skipped/.test(r.summary));
    check('search: no YARA/signature type is declared', !search.manifest.io.produces.some((t) => t.name === 'signature'));
}
{
    const graph = makeGraph();
    const net = makeNet(() => ({ status: 200, body: '' }));
    const r = await search.run(RUN(net, graph, { query: 'relayshell', category: 'yara' }));
    check('search: the YARA category is refused without a request', net.calls.length === 0 && /not staged yet/.test(r.summary));
    check('lookup: no YARA/signature type is consumed', !lookup.manifest.io.consumes.some((t) => t.name === 'signature'));
}

// ================================================================ search: wallets
// The Cryptocurrency pack's type, with the network the format settles. Values are real rows of the
// site's wallet category (2026-11-14), which lists EVM addresses both checksummed and in lower case.
function walletSearchPage(values) {
    const articles = values
        .map(
            (v) => `<article>
    <div><hgroup><h4><a href="/iocs/${v}/">${v}</a></h4><h5>WALLET</h5></hgroup></div>
    <div>First seen: 2026-11-01 • Last seen: 2026-11-02</div>
</article>`,
        )
        .join('\n');
    return `<p>${values.length} IoCs</p>
<div id="list-view" class="view-container">
${articles}
</div>
<div id="grid-view"></div>`;
}
const WALLETS = [
    'bc1q5hjy0shhu5eqakqm7ptqquaam7phhw9p988ec6',
    'TZG47zhb8kcriWQ2rE719yHs1KqgzwMrvF',
    '0x8d53903625b8e839b9DF4bd28B0EFb1CD6b8639A',
    '0x80358c5b8f9b2cc27147a1e0f2a6c9a30eb2c397',
];
{
    const graph = makeGraph();
    const net = makeNet(() => ({ status: 200, body: walletSearchPage(WALLETS) }));
    const r = await search.run(RUN(net, graph, { query: '0x', category: 'wallet' }));
    const byAddress = Object.fromEntries(graph.created.map((n) => [n.data.address, n]));
    check('search wallet: four nodes, all of the Cryptocurrency pack type', graph.created.length === 4 && graph.created.every((n) => n.type === 'cryptocurrency.crypto_address'));
    check('search wallet: nothing written as the older Financial type', !graph.created.some((n) => n.type === 'financial.crypto_address'));
    check('search wallet: bc1 is bitcoin', byAddress['bc1q5hjy0shhu5eqakqm7ptqquaam7phhw9p988ec6']?.data.network === 'bitcoin');
    check('search wallet: T… is tron', byAddress['TZG47zhb8kcriWQ2rE719yHs1KqgzwMrvF']?.data.network === 'tron');
    check(
        'search wallet: a checksummed 0x address is written in lower case on evm',
        byAddress['0x8d53903625b8e839b9df4bd28b0efb1cd6b8639a']?.data.network === 'evm',
    );
    check(
        'search wallet: the provenance URL keeps the site’s own spelling',
        byAddress['0x8d53903625b8e839b9df4bd28b0efb1cd6b8639a']?.data.lazarus_day_url === 'https://lazarus.day/iocs/0x8d53903625b8e839b9DF4bd28B0EFb1CD6b8639A/',
    );
    check('search wallet: counted as crypto addresses', r.counts.wallets === 4 && /4 crypto addresses/.test(r.summary));
    check('search wallet: io declares the Cryptocurrency type', search.manifest.io.produces.some((t) => t.typepack === 'run.vineyard.typepacks.cryptocurrency' && t.name === 'crypto_address'));
    check('search wallet: io no longer declares the Financial type', !search.manifest.io.produces.some((t) => t.category === 'financial'));
}
{
    // A project without the Cryptocurrency pack (or with one older than the network written)
    // refuses the create. That is the project's state, not a bad value, so the summary says what to
    // install instead of folding it into "refused by the installed typepack".
    const graph = makeGraph();
    const createNode = graph.createNode;
    graph.createNode = async (draft) => {
        if (draft.type === 'cryptocurrency.crypto_address') throw new Error(`type "${draft.type}" is not defined by any installed typepack.`);
        return createNode(draft);
    };
    const net = makeNet(() => ({ status: 200, body: walletSearchPage(WALLETS.slice(0, 2)) }));
    const r = await search.run(RUN(net, graph, { query: 'x', category: 'wallet' }));
    check('search wallet refused: nothing staged, the run does not abort', graph.created.length === 0 && r.counts.wallets_refused === 2);
    check('search wallet refused: the summary names the type pack to install', /install or update the Cryptocurrency type pack/.test(r.summary));
    check('search wallet refused: not double-reported as generic refusals', !/value\(s\) were refused by the installed typepack/.test(r.summary));
}
{
    const graph = makeGraph({
        w1: { id: 'w1', type: 'cryptocurrency.crypto_address', data: { network: 'evm', address: '0x8d53903625b8e839b9df4bd28b0efb1cd6b8639a' } },
        w2: { id: 'w2', type: 'financial.crypto_address', data: { address: 'TZG47zhb8kcriWQ2rE719yHs1KqgzwMrvF' } },
    });
    const net = makeNet(() => ({ status: 404 }));
    const r = await lookup.run(RUN(net, graph, {}, ['w1', 'w2']));
    check(
        'lookup wallet: both address types are looked up, a 0x address under each spelling the site uses',
        net.calls.length === 3 &&
            net.calls[0].url === 'https://lazarus.day/iocs/0x8d53903625b8e839b9df4bd28b0efb1cd6b8639a/?utm_source=vineyard' &&
            net.calls[1].url === 'https://lazarus.day/iocs/0x8d53903625b8e839b9DF4bd28B0EFb1CD6b8639A/?utm_source=vineyard' &&
            net.calls[2].url === 'https://lazarus.day/iocs/TZG47zhb8kcriWQ2rE719yHs1KqgzwMrvF/?utm_source=vineyard',
    );
    check('lookup wallet: 404 on every spelling is one indicator not listed', r.counts.not_listed === 2 && r.counts.looked === 2);
    check(
        'lookup wallet: io consumes both crypto address types',
        ['financial', 'cryptocurrency'].every((c) => lookup.manifest.io.consumes.some((t) => t.category === c && t.name === 'crypto_address')),
    );
}

// ================================================================ wallets: the site's spellings
// lazarus.day keys a record by the exact string a report printed and answers 404 for any other
// spelling, while the node holds the type pack's lower-case form. Measured 2026-11-14:
// /iocs/0x10E0…C045E/ is 200 and /iocs/0x10e0…c045e/ is 404; 0x8d53…639A and 0x8d53…639a are two
// records with different reports.
const CHECKSUMMED = '0x8d53903625b8e839b9DF4bd28B0EFb1CD6b8639A';
const LOWER = CHECKSUMMED.toLowerCase();
const recordPath = (v) => `https://lazarus.day/iocs/${v}/?utm_source=vineyard`;
const nodesOf = (graph) => Object.fromEntries(graph.created.map((n) => [n.id, n]));
{
    // Checksummed only: the site's usual case. Search writes the lower-case node; Lookup on that
    // node must still find the record and call it listed.
    const site = (url) =>
        url.includes('?q=')
            ? { status: 200, body: walletSearchPage([CHECKSUMMED]) }
            : url === recordPath(CHECKSUMMED)
              ? { status: 200, body: fixture('detail-wallet-checksummed.html') }
              : { status: 404 };
    const found = makeGraph();
    await search.run(RUN(makeNet(site), found, { query: '0x8d53', category: 'wallet' }));
    const node = found.created[0];
    check('wallet spellings: search writes the lower-case address', node?.data.address === LOWER && node?.data.network === 'evm');

    const graph = makeGraph(nodesOf(found));
    const net = makeNet(site);
    const r = await lookup.run(RUN(net, graph, {}, [node.id]));
    check('wallet spellings: lookup asks for the checksummed record', net.calls.some((c) => c.url === recordPath(CHECKSUMMED)));
    check('wallet spellings: a checksummed-only record is listed, not a negative', r.counts.listed === 1 && r.counts.not_listed === 0 && !/not listed/.test(r.summary));
    check('wallet spellings: its report is added', r.counts.reports === 1 && graph.edges.some((e) => e.label === 'reported in'));
    check(
        'wallet spellings: the node keeps pointing at the record that exists',
        graph.updates[0]?.data.lazarus_day_url === `https://lazarus.day/iocs/${CHECKSUMMED}/`,
    );
}
{
    // Both spellings are records: both are read, both reports are added, the dates are the widest,
    // and the node's own record URL stays.
    const graph = makeGraph({
        w: {
            id: 'w',
            type: 'cryptocurrency.crypto_address',
            data: { network: 'evm', address: LOWER, lazarus_day_url: `https://lazarus.day/iocs/${CHECKSUMMED}/` },
        },
    });
    const net = makeNet((url) =>
        url === recordPath(CHECKSUMMED)
            ? { status: 200, body: fixture('detail-wallet-checksummed.html') }
            : url === recordPath(LOWER)
              ? { status: 200, body: fixture('detail-wallet-lower.html') }
              : { status: 404 },
    );
    const r = await lookup.run(RUN(net, graph, {}, ['w']));
    check('wallet two records: each spelling is requested once', net.calls.length === 2 && net.calls[0].url === recordPath(CHECKSUMMED));
    check('wallet two records: one indicator, listed', r.counts.looked === 1 && r.counts.listed === 1);
    check('wallet two records: the reports of both records are added', r.counts.reports === 2 && graph.created.filter((n) => n.type === 'threat.campaign').length === 2);
    const patch = graph.updates[0]?.data ?? {};
    check(
        'wallet two records: earliest first-seen and latest last-seen across both',
        patch.lazarus_day_first_seen === '2026-10-30' && patch.lazarus_day_last_seen === '2026-11-07',
    );
    check('wallet two records: the node’s own record URL stays', patch.lazarus_day_url === `https://lazarus.day/iocs/${CHECKSUMMED}/`);
}
{
    // One search page listing both spellings: one node, counted once, the first row's URL, the
    // widest dates — not whichever row came last.
    const page = `<p>2 IoCs</p>
<div id="list-view" class="view-container">
<article>
    <div><hgroup><h4><a href="/iocs/${CHECKSUMMED}/">${CHECKSUMMED}</a></h4><h5>WALLET</h5></hgroup></div>
    <div>First seen: 2026-11-06 • Last seen: 2026-11-06</div>
</article>
<article>
    <div><hgroup><h4><a href="/iocs/${LOWER}/">${LOWER}</a></h4><h5>WALLET</h5></hgroup></div>
    <div>First seen: 2026-10-30 • Last seen: 2026-11-07</div>
</article>
</div>
<div id="grid-view"></div>`;
    const graph = makeGraph();
    const r = await search.run(RUN(makeNet(() => ({ status: 200, body: page })), graph, { query: '0x8d53', category: 'wallet' }));
    const last = graph.created[graph.created.length - 1]?.data ?? {};
    check('search wallet spellings: counted as one crypto address', r.counts.wallets === 1 && r.counts.iocs === 1 && r.counts.wallet_spellings_merged === 1);
    check(
        'search wallet spellings: the last write carries the first row’s URL and the widest dates',
        last.lazarus_day_url === `https://lazarus.day/iocs/${CHECKSUMMED}/` &&
            last.lazarus_day_first_seen === '2026-10-30' &&
            last.lazarus_day_last_seen === '2026-11-07',
    );
    check('search wallet spellings: the summary says they were merged', /another spelling of the same address/.test(r.summary));
}

// ================================================================ search: hash records
const HASH_SHA256 = '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c';
const HASH_MD5 = 'db349b97c37d22f5ea1d1841e3c89eb4';

function hashSearchPage(values) {
    const articles = values
        .map(
            (v) => `<article>
    <div><hgroup><h4><a href="/iocs/${v}/">${v}</a></h4><h5>HASH</h5></hgroup></div>
    <div>First seen: 2026-10-21 • Last seen: 2026-10-21</div>
</article>`,
        )
        .join('\n');
    return `<p>${values.length} IoCs</p>
<div id="list-view" class="view-container">
${articles}
</div>
<div id="grid-view"></div>`;
}

{
    // The list shows only the digest the record is keyed by; the record page has the file's MD5,
    // SHA-1 and SHA-256. The node should carry all three, not just the one that was listed.
    const graph = makeGraph();
    const net = makeNet((url) =>
        url.includes('?q=') ? { status: 200, body: hashSearchPage([HASH_SHA256]) } : { status: 200, body: fixture('detail-hash.html') },
    );
    const r = await search.run(RUN(net, graph, { query: HASH_SHA256 }));
    check(
        'search hash: the record page is fetched with the source tag',
        net.calls.length === 2 && net.calls[1].url === `https://lazarus.day/iocs/${HASH_SHA256}/?utm_source=vineyard`,
    );
    const node = graph.created.find((n) => n.type === 'threat.file_hash');
    check('search hash: one File Hash node', graph.created.length === 1 && !!node);
    check('search hash: SHA-256 is the identity', node?.data.sha256 === HASH_SHA256);
    check('search hash: the stored record URL stays clean', node?.data.lazarus_day_url === `https://lazarus.day/iocs/${HASH_SHA256}/`);
    check('search hash: MD5 filled from the record', node?.data.md5 === HASH_MD5);
    check('search hash: SHA-1 filled from the record', node?.data.sha1 === 'e889544aff85ffaf8b0d0da705105dee7c97fe26');
    check('search hash: a clean resolution reports no failure', !/could not be fetched|had no SHA-256|not resolved/.test(r.summary));
}
{
    // The searched value is an MD5; the site returns the SHA-256 record. The node must be a File
    // Hash (sha256 is required by the typepack), with the MD5 attached, not an MD5 Indicator.
    const graph = makeGraph();
    const net = makeNet((url) =>
        url.includes('?q=') ? { status: 200, body: hashSearchPage([HASH_MD5]) } : { status: 200, body: fixture('detail-hash.html') },
    );
    const r = await search.run(RUN(net, graph, { query: HASH_MD5 }));
    const node = graph.created.find((n) => n.type === 'threat.file_hash');
    check('search hash: an MD5 result is promoted to a File Hash', !!node && node.data.sha256 === HASH_SHA256 && node.data.md5 === HASH_MD5);
    check('search hash: no MD5-only Indicator is staged', !graph.created.some((n) => n.type === 'threat.indicator'));
}
{
    const graph = makeGraph();
    const net = makeNet((url) => (url.includes('?q=') ? { status: 200, body: hashSearchPage([HASH_SHA256]) } : { status: 404 }));
    const r = await search.run(RUN(net, graph, { query: HASH_SHA256 }));
    const node = graph.created.find((n) => n.type === 'threat.file_hash');
    check(
        'search hash: a failed record page falls back to the listed digest',
        node?.data.sha256 === HASH_SHA256 && /could not be fetched/.test(r.summary),
    );
}
{
    // A challenge on the first record page stops resolution for the rest of the run; the remaining
    // rows still produce nodes from their listed digest, and the summary accounts for both.
    const other = 'b'.repeat(64);
    const graph = makeGraph();
    const net = makeNet((url) =>
        url.includes('?q=') ? { status: 200, body: hashSearchPage([HASH_SHA256, other]) } : { status: 403, body: '<title>Just a moment...</title>' },
    );
    const r = await search.run(RUN(net, graph, { query: HASH_SHA256 }));
    check('search hash: a challenge stops further record fetches', net.calls.length === 2);
    check('search hash: the failed and skipped fetches are both stated', /could not be fetched/.test(r.summary) && /not resolved/.test(r.summary));
    check('search hash: both rows still produce nodes', graph.created.length === 2);
    check('search hash: no hash counters are returned', !('hashes_resolved' in r.counts) && !('hashes_unresolved' in r.counts) && !('hashes_skipped' in r.counts));
}

{
    // A record that is only an MD5 (SHA1/SHA256 both "-") cannot be a file_hash: sha256 is required.
    // It becomes an Indicator with indicator_type, and the run says why instead of calling it a
    // failed lookup.
    const md5 = '1b668cb3fcd7243e258ba4d9473d64af';
    const detail = `<main class="container"><section><hgroup><h2>${md5}</h2><h3>Hash</h3></hgroup>
<div><ul><li>MD5: ${md5}</li><li>SHA1: -</li><li>SHA256: -</li>
<li>First Seen: 2026-10-20</li><li>Last Seen: 2026-10-20</li></ul></div></section></main>`;
    const graph = makeGraph();
    const net = makeNet((url) => (url.includes('?q=') ? { status: 200, body: hashSearchPage([md5]) } : { status: 200, body: detail }));
    const r = await search.run(RUN(net, graph, { query: md5 }));
    const node = graph.created.find((n) => n.type === 'threat.indicator');
    check('search hash: a record without SHA-256 becomes an Indicator', node?.data.indicator_type === 'md5' && node?.data.value === md5);
    check('search hash: no File Hash node is invented without SHA-256', !graph.created.some((n) => n.type === 'threat.file_hash'));
    check('search hash: the missing SHA-256 is stated, not called a fetch failure', /had no SHA-256/.test(r.summary) && !/could not be fetched/.test(r.summary));
}

// ================================================================ lookup: domain
{
    const graph = makeGraph({
        d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'blockchain-newtech.com' } },
    });
    const net = makeNet(() => ({ status: 200, body: fixture('detail-domain.html') }));
    const r = await lookup.run(RUN(net, graph, {}, ['d1']));

    check(
        'lookup: exact record URL with the source tag, no search',
        net.calls.length === 1 && net.calls[0].url === 'https://lazarus.day/iocs/blockchain-newtech.com/?utm_source=vineyard',
    );
    check(
        'lookup: the recorded provenance URL stays clean',
        graph.updates[0].data.lazarus_day_url === 'https://lazarus.day/iocs/blockchain-newtech.com/',
    );
    check('lookup: the selected node is enriched, not duplicated', graph.updates.length === 1 && graph.updates[0].id === 'd1');
    check('lookup: record dates written onto the node', graph.updates[0].data.lazarus_day_first_seen === '2023-12-08');
    check('lookup: five reports become five Campaigns', graph.created.filter((n) => n.type === 'threat.campaign').length === 5);
    check('lookup: five "reported in" edges', graph.edges.filter((e) => e.label === 'reported in').length === 5);
    check(
        'lookup: campaign carries the report URL and date',
        graph.created.some(
            (n) => n.type === 'threat.campaign' && n.data.start_date === '2024-05-28' && String(n.data.lazarus_day_url).includes('/reports/'),
        ),
    );
    check(
        'lookup: campaign description attributes the publisher',
        graph.created.some((n) => n.type === 'threat.campaign' && /Report by Microsoft/.test(n.data.description)),
    );
    check(
        'lookup: campaign and related URLs stay clean of utm_source',
        graph.created.every((n) => !String(n.data.lazarus_day_url ?? '').includes('utm_source')),
    );
    check('lookup: resolved IP added as a node', graph.created.some((n) => n.type === 'infrastructure.ip_address' && n.data.ip_address === '160.16.200.77'));
    check('lookup: URL on the domain added as a node', graph.created.some((n) => n.type === 'web.url' && n.data.url === 'https://blockchain-newtech.com/download/download.asp'));
    check(
        'lookup: related edges use the house labels',
        graph.edges.some((e) => e.label === 'resolves to') && graph.edges.some((e) => e.label === 'hosts'),
    );
    check('lookup: summary reports the reports and the caveat', /5 reports/.test(r.summary) && /automatically extracted/.test(r.summary));
}
{
    // The same report reached from two seeds is one Campaign, not two.
    const graph = makeGraph({
        d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'blockchain-newtech.com' } },
        d2: { id: 'd2', type: 'infrastructure.domain', data: { domain_name: 'blockchain-newtech.com' } },
    });
    const net = makeNet(() => ({ status: 200, body: fixture('detail-domain.html') }));
    await lookup.run(RUN(net, graph, { include_related_iocs: false }, ['d1', 'd2']));
    check('lookup: campaigns are shared across seeds in one run', graph.created.filter((n) => n.type === 'threat.campaign').length === 5);
    check('lookup: both seeds link to them', graph.edges.filter((e) => e.label === 'reported in').length === 10);
    check('lookup: related IoCs can be turned off', !graph.created.some((n) => n.type === 'web.url'));
}
{
    const graph = makeGraph({ d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'nope.example' } } });
    const net = makeNet(() => ({ status: 404, body: fixture('not-found.html') }));
    const r = await lookup.run(RUN(net, graph, {}, ['d1']));
    check('lookup: 404 is a real negative', r.counts.not_listed === 1 && r.counts.failed === 0);
    check('lookup: nothing written for a 404', graph.updates.length === 0 && graph.created.length === 0);
    check('lookup: summary says not listed, not failed', /not listed|None of the/.test(r.summary) && !/lookup\(s\) failed/.test(r.summary));
}

// ================================================================ lookup: IP
{
    const graph = makeGraph({ i1: { id: 'i1', type: 'infrastructure.ip_address', data: { ip_address: '23.27.13.72' } } });
    const net = makeNet(() => ({ status: 200, body: fixture('detail-ip.html') }));
    const r = await lookup.run(RUN(net, graph, { include_related_iocs: false }, ['i1']));
    check('lookup ip: asn written onto the IP as an integer', graph.updates[0].data.asn === 149440);
    check('lookup ip: ASN name kept in a namespaced extra', graph.updates[0].data.lazarus_day_asn_name === 'Evoxt Sdn. Bhd.');
    check('lookup ip: country and coordinates kept', graph.updates[0].data.lazarus_day_country === 'United Kingdom');
    check('lookup ip: an AS node is created', graph.created.some((n) => n.type === 'infrastructure.autonomous_system' && n.data.autonomous_system_number === 149440));
    check('lookup ip: linked "announced by"', graph.edges.some((e) => e.label === 'announced by'));
    check('lookup ip: one report campaign', graph.created.filter((n) => n.type === 'threat.campaign').length === 1);
}

// ================================================================ lookup: hash fallback
{
    const sha256 = 'a'.repeat(64);
    const sha1 = 'b'.repeat(40);
    const md5 = 'db349b97c37d22f5ea1d1841e3c89eb4';
    const graph = makeGraph({ h1: { id: 'h1', type: 'threat.file_hash', data: { sha256, sha1, md5 } } });
    const net = makeNet((url) => {
        if (url.includes(md5)) return { status: 200, body: fixture('detail-hash.html') };
        return { status: 404 };
    });
    const r = await lookup.run(RUN(net, graph, { include_related_iocs: false }, ['h1']));
    check('lookup hash: tries sha256, then sha1, then md5', net.calls.length === 3);
    check('lookup hash: found under the MD5', r.counts.listed === 1);
    check('lookup hash: md5 and sha1 merged onto the node', graph.updates[0].data.md5 === md5 && graph.updates[0].data.sha1 === 'e889544aff85ffaf8b0d0da705105dee7c97fe26');
    check('lookup hash: the identity sha256 is never rewritten', !('sha256' in graph.updates[0].data));
    check('lookup hash: the site\'s sha256 kept as an extra', graph.updates[0].data.lazarus_day_sha256 === '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c');
}

// ================================================================ scope, challenge, types
{
    // The whole point of the change: one declared origin/path, not an arbitrary-host probe.
    for (const [name, plugin] of [['search', search], ['lookup', lookup]]) {
        const network = plugin.manifest.scopes.network || [];
        check(`${name}: exactly one declared network endpoint`, network.length === 1);
        check(`${name}: the endpoint is https://lazarus.day/iocs`, network[0]?.endpoint === 'https://lazarus.day/iocs');
        check(`${name}: GET only`, JSON.stringify(network[0]?.methods) === '["GET"]');
        check(`${name}: no web_probe`, !plugin.manifest.scopes.web_probe);
    }
}
{
    const graph = makeGraph({ u1: { id: 'u1', type: 'web.url', data: { url: 'https://cubedesign.co.kr/news' } } });
    const net = makeNet(() => ({ status: 200, body: fixture('detail-url.html') }));
    const r = await lookup.run(RUN(net, graph, { include_related_iocs: false }, ['u1']));
    check('lookup: URL value is double-encoded in the path', net.calls.length === 1 && net.calls[0].url.includes('%253A%252F'));
    check('lookup URL: the request carries the source tag', net.calls[0].url.includes('utm_source=vineyard'));
    check('lookup: URL record parsed', r.counts.listed === 1);
}
{
    const graph = makeGraph();
    const net = makeNet(() => ({ status: 200, body: fixture('search-blockchain.html') }));
    const r = await search.run(ctxOnWeb(net, graph, { query: 'blockchain' }));
    check('search: web build refuses without a request', net.calls.length === 0 && /desktop app/.test(r.summary));
}
{
    const graph = makeGraph();
    const r = await search.run(RUN(null, graph, { query: 'blockchain' }));
    check('search: missing network capability is named, not attempted', /Network access was not granted/.test(r.summary));
}
{
    const graph = makeGraph({ d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'x.example' } } });
    const net = makeNet(() => ({ status: 403, body: '<title>Attention Required! | Cloudflare</title>' }));
    const r = await lookup.run(RUN(net, graph, {}, ['d1']));
    check('lookup: challenge counted separately', r.counts.blocked === 1 && r.counts.not_listed === 0 && r.counts.failed === 0);
}
{
    const graph = makeGraph({ m1: { id: 'm1', type: 'threat.malware', data: { name: 'x' } } });
    const net = makeNet(() => ({ status: 200, body: '' }));
    const r = await lookup.run(RUN(net, graph, {}, ['m1']));
    check('lookup: an unsupported node type makes no request', net.calls.length === 0 && r.counts.unsupported === 1);
}

// ================================================================ lookup: ASN cap
{
    const graph = makeGraph({ a1: { id: 'a1', type: 'infrastructure.autonomous_system', data: { autonomous_system_number: 149440 } } });
    const net = makeNet(() => ({ status: 200, body: fixture('detail-asn.html') }));
    const r = await lookup.run(RUN(net, graph, { include_related_iocs: true, max_related_iocs: 10 }, ['a1']));
    check('lookup asn: the AS organisation is written onto the node', graph.updates[0].data.autonomous_system_name === 'Evoxt Sdn. Bhd.');
    check('lookup asn: related IPs are capped', graph.created.filter((n) => n.type === 'infrastructure.ip_address').length === 10);
    check('lookup asn: the cap is stated in the summary', /left out \(limit 10\)/.test(r.summary));
    check('lookup asn: IPs link from the ASN', graph.edges.filter((e) => e.label === 'announces').length === 10);
}

// ================================================================ the pack page
// The catalog's About: at most about 1,500 characters, nothing about Vineyard itself. 1.6.0's
// wallet-network note took it to 1,864 before it was cut back.
{
    const m = JSON.parse(readFileSync(new URL('./plugins/lazarusday.manifest.json', import.meta.url), 'utf8'));
    check(`pack page: the JSON is the bundle's`, m.description === pack.description && m.summary === pack.summary);
    check(`pack page: at most 1,500 characters (${pack.description.length})`, pack.description.length <= 1500);
    check('pack page: nothing about how Vineyard installs or stages', !/type pack|typepack|review|staged/i.test(pack.description));
}

// ================================================================ report
if (fail.length) {
    console.error(`test-plugin: ${fail.length} failure(s)`);
    for (const f of fail) console.error(`  - ${f}`);
    process.exit(1);
}
console.log(`test-plugin: all ${ok.length} checks passed`);
