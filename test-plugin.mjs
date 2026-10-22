// Functional test harness for dist/pack.mjs — the run() bodies, not just the parsers.
//
// The parsers are covered by src/selftest.ts. What is left is everything that needs a ctx: what
// gets requested, what gets written, and — as important — what the summary says when the answer is
// "not listed" rather than "failed". The probe is mocked with the same fixture pages the parser
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

function makeProbe(respond) {
    const calls = [];
    return {
        calls,
        async probe(url, init) {
            calls.push({ url, init });
            const r = respond(url) ?? { status: 404 };
            return {
                status: r.status,
                headers: r.headers ?? {},
                body: r.body ?? '',
                truncated: !!r.truncated,
                redirectUrl: r.redirectUrl,
                error: r.error,
            };
        },
    };
}

function ctxOf({ probe, graph, params, selection = [] }) {
    return {
        net: probe ? { probe: probe.probe } : {},
        graph,
        input: { selection },
        params,
        config: {},
        signal: new AbortController().signal,
        progress: { set() {} },
    };
}

const RUN = (probe, graph, params, selection = []) => ctxOf({ probe, graph, params, selection });

// ================================================================ search
{
    const graph = makeGraph();
    const probe = makeProbe(() => ({ status: 200, body: fixture('search-blockchain.html') }));
    const r = await search.run(RUN(probe, graph, { query: 'blockchain', pages: 1 }));

    check('search: one request for one page', probe.calls.length === 1);
    check('search: query in the URL', probe.calls[0].url.includes('q=blockchain'));
    check('search: no category param for "all"', !probe.calls[0].url.includes('category='));
    check('search: 15 nodes staged', graph.created.length === 15);
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
    const probe = makeProbe((url) =>
        url.includes('page=2') ? { status: 404 } : { status: 200, body: fixture('search-blockchain.html') },
    );
    const r = await search.run(RUN(probe, graph, { query: 'blockchain', category: 'domain', pages: 2 }));
    check('search: page 2 requested', probe.calls.length === 2 && probe.calls[1].url.includes('page=2'));
    check('search: category kept on every page', probe.calls.every((c) => c.url.includes('category=domain')));
    check('search: past-the-end 404 is not a failure', r.counts.failed === 0 && r.counts.pages === 1);
    check('search: nodes from page 1 staged', graph.created.length === 15);
}
{
    const graph = makeGraph();
    const probe = makeProbe(() => ({ status: 200, body: fixture('search-empty.html') }));
    const r = await search.run(RUN(probe, graph, { query: 'zzzznotfoundzzzz' }));
    check('search: empty result stages nothing', graph.created.length === 0);
    check('search: empty result is called a real negative', /lists no indicator matching/.test(r.summary));
}
{
    const graph = makeGraph();
    const probe = makeProbe(() => ({ status: 403, body: '<title>Just a moment...</title>' }));
    const r = await search.run(RUN(probe, graph, { query: 'blockchain' }));
    check('search: challenge is counted as blocked, not as zero results', r.counts.blocked === 1 && graph.created.length === 0);
    check('search: challenge is named in the summary', /bot challenge/.test(r.summary));
}
{
    const graph = makeGraph();
    const r = await search.run({ ...RUN(null, graph, { query: 'x' }) });
    check('search: web build gets the desktop explanation', /desktop app/.test(r.summary));
}
{
    const graph = makeGraph();
    const probe = makeProbe(() => ({ status: 200, body: fixture('search-blockchain.html') }));
    const r = await search.run(RUN(probe, graph, { query: '   ' }));
    check('search: blank query refuses before any request', probe.calls.length === 0 && /Enter a search keyword/.test(r.summary));
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
    const probe = makeProbe(() => ({ status: 200, body: yaraPage }));
    const r = await search.run(RUN(probe, graph, { query: 'relayshell' }));
    check('search: a YARA row stages nothing', graph.created.length === 0);
    check('search: a YARA row is counted, not hidden', r.counts.skipped_yara === 1);
    check('search: the skip is stated in the summary', /YARA rule result was skipped/.test(r.summary));
    check('search: no YARA/signature type is declared', !search.manifest.io.produces.some((t) => t.name === 'signature'));
}
{
    const graph = makeGraph();
    const probe = makeProbe(() => ({ status: 200, body: '' }));
    const r = await search.run(RUN(probe, graph, { query: 'relayshell', category: 'yara' }));
    check('search: the YARA category is refused without a request', probe.calls.length === 0 && /not staged yet/.test(r.summary));
    check('lookup: no YARA/signature type is consumed', !lookup.manifest.io.consumes.some((t) => t.name === 'signature'));
}

// ================================================================ lookup: domain
{
    const graph = makeGraph({
        d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'blockchain-newtech.com' } },
    });
    const probe = makeProbe(() => ({ status: 200, body: fixture('detail-domain.html') }));
    const r = await lookup.run(RUN(probe, graph, {}, ['d1']));

    check('lookup: exact record URL, no search', probe.calls.length === 1 && probe.calls[0].url === 'https://lazarus.day/iocs/blockchain-newtech.com/');
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
    const probe = makeProbe(() => ({ status: 200, body: fixture('detail-domain.html') }));
    await lookup.run(RUN(probe, graph, { include_related_iocs: false }, ['d1', 'd2']));
    check('lookup: campaigns are shared across seeds in one run', graph.created.filter((n) => n.type === 'threat.campaign').length === 5);
    check('lookup: both seeds link to them', graph.edges.filter((e) => e.label === 'reported in').length === 10);
    check('lookup: related IOCs can be turned off', !graph.created.some((n) => n.type === 'web.url'));
}
{
    const graph = makeGraph({ d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'nope.example' } } });
    const probe = makeProbe(() => ({ status: 404, body: fixture('not-found.html') }));
    const r = await lookup.run(RUN(probe, graph, {}, ['d1']));
    check('lookup: 404 is a real negative', r.counts.not_listed === 1 && r.counts.failed === 0);
    check('lookup: nothing written for a 404', graph.updates.length === 0 && graph.created.length === 0);
    check('lookup: summary says not listed, not failed', /not listed|None of the/.test(r.summary) && !/lookup\(s\) failed/.test(r.summary));
}

// ================================================================ lookup: IP
{
    const graph = makeGraph({ i1: { id: 'i1', type: 'infrastructure.ip_address', data: { ip_address: '23.27.13.72' } } });
    const probe = makeProbe(() => ({ status: 200, body: fixture('detail-ip.html') }));
    const r = await lookup.run(RUN(probe, graph, { include_related_iocs: false }, ['i1']));
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
    const probe = makeProbe((url) => {
        if (url.includes(md5)) return { status: 200, body: fixture('detail-hash.html') };
        return { status: 404 };
    });
    const r = await lookup.run(RUN(probe, graph, { include_related_iocs: false }, ['h1']));
    check('lookup hash: tries sha256, then sha1, then md5', probe.calls.length === 3);
    check('lookup hash: found under the MD5', r.counts.listed === 1);
    check('lookup hash: md5 and sha1 merged onto the node', graph.updates[0].data.md5 === md5 && graph.updates[0].data.sha1 === 'e889544aff85ffaf8b0d0da705105dee7c97fe26');
    check('lookup hash: the identity sha256 is never rewritten', !('sha256' in graph.updates[0].data));
    check('lookup hash: the site\'s sha256 kept as an extra', graph.updates[0].data.lazarus_day_sha256 === '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c');
}

// ================================================================ lookup: redirects, challenge, types
{
    const graph = makeGraph({ u1: { id: 'u1', type: 'web.url', data: { url: 'https://cubedesign.co.kr/news' } } });
    let hop = 0;
    const probe = makeProbe(() =>
        ++hop === 1
            ? { status: 301, redirectUrl: '/iocs/https%253A%252F%252Fcubedesign.co.kr%252Fnews/' }
            : { status: 200, body: fixture('detail-url.html') },
    );
    const r = await lookup.run(RUN(probe, graph, { include_related_iocs: false }, ['u1']));
    check('lookup: a redirect is followed by hand', probe.calls.length === 2 && r.counts.listed === 1);
    check('lookup: a relative redirect resolves against the requested URL', probe.calls[1].url === probe.calls[0].url);
    check('lookup: URL value is double-encoded in the path', probe.calls[0].url.includes('%253A%252F'));
}
{
    const graph = makeGraph({ d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'x.example' } } });
    const probe = makeProbe(() => ({ status: 403, body: '<title>Attention Required! | Cloudflare</title>' }));
    const r = await lookup.run(RUN(probe, graph, {}, ['d1']));
    check('lookup: challenge counted separately', r.counts.blocked === 1 && r.counts.not_listed === 0 && r.counts.failed === 0);
}
{
    const graph = makeGraph({ m1: { id: 'm1', type: 'threat.malware', data: { name: 'x' } } });
    const probe = makeProbe(() => ({ status: 200, body: '' }));
    const r = await lookup.run(RUN(probe, graph, {}, ['m1']));
    check('lookup: an unsupported node type makes no request', probe.calls.length === 0 && r.counts.unsupported === 1);
}

// ================================================================ lookup: ASN cap
{
    const graph = makeGraph({ a1: { id: 'a1', type: 'infrastructure.autonomous_system', data: { autonomous_system_number: 149440 } } });
    const probe = makeProbe(() => ({ status: 200, body: fixture('detail-asn.html') }));
    const r = await lookup.run(RUN(probe, graph, { include_related_iocs: true, max_related_iocs: 10 }, ['a1']));
    check('lookup asn: the AS organisation is written onto the node', graph.updates[0].data.autonomous_system_name === 'Evoxt Sdn. Bhd.');
    check('lookup asn: related IPs are capped', graph.created.filter((n) => n.type === 'infrastructure.ip_address').length === 10);
    check('lookup asn: the cap is stated in the summary', /left out \(limit 10\)/.test(r.summary));
    check('lookup asn: IPs link from the ASN', graph.edges.filter((e) => e.label === 'announces').length === 10);
}

// ================================================================ report
if (fail.length) {
    console.error(`test-plugin: ${fail.length} failure(s)`);
    for (const f of fail) console.error(`  - ${f}`);
    process.exit(1);
}
console.log(`test-plugin: all ${ok.length} checks passed`);
