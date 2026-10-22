// Live check against lazarus.day — the one thing the mocked tests cannot prove.
//
// Run: npm run live   (after npm run build)
//
// It drives the bundled plugins with a real `probe` built on Node's fetch, in place of the Electron
// main-process one. The contract is the same shape (`{status, headers, body, truncated,
// redirectUrl, error}`), so a pass here means the selectors, the double-encoded paths and the
// redirect handling all still match the live site. It only reads: graph writes are collected in
// memory and printed, never sent anywhere.
//
// This is a check, not a test: the site's contents change, so the assertions are about shape and
// plausibility (something was found, the record page parsed, a known-negative stayed negative).
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

async function probe(url, init = {}) {
    const res = await fetch(url, {
        method: init.method ?? 'GET',
        headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml' },
        redirect: 'manual',
        signal: AbortSignal.timeout(init.timeoutMs ?? 20_000),
    });
    const buf = Buffer.from(await res.arrayBuffer());
    const max = init.maxBytes ?? 1_500_000;
    return {
        status: res.status,
        headers: Object.fromEntries(res.headers),
        body: buf.subarray(0, max).toString('utf8'),
        truncated: buf.length > max,
        redirectUrl: res.headers.get('location') ?? undefined,
    };
}

function memoryGraph(seed = {}) {
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

const ctx = (graph, params, selection = []) => ({
    net: { probe },
    graph,
    input: { selection },
    params,
    config: {},
    signal: new AbortController().signal,
    progress: { set() {} },
});

const { default: pack } = await import('./dist/pack.mjs');
const [search, lookup] = pack.plugins;

let bad = 0;
const expect = (cond, msg) => {
    console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${msg}`);
    if (!cond) bad++;
};

console.log('search: q=blockchain (page 1)');
{
    const graph = memoryGraph();
    const r = await search.run(ctx(graph, { query: 'blockchain', pages: 1 }));
    console.log(`  summary: ${r.summary}`);
    expect(r.counts.iocs > 0, `staged ${r.counts.iocs} nodes`);
    expect(r.counts.failed === 0, 'no request failed');
    expect(graph.created.every((n) => n.data.lazarus_day_url), 'every node carries its record URL');
    const sample = graph.created.slice(0, 3).map((n) => `${n.type} ${Object.values(n.data)[0]}`);
    console.log(`  sample: ${sample.join(' | ')}`);
}

console.log('lookup: a listed domain (blockchain-newtech.com)');
{
    const graph = memoryGraph({
        d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'blockchain-newtech.com' } },
    });
    const r = await lookup.run(ctx(graph, {}, ['d1']));
    console.log(`  summary: ${r.summary}`);
    expect(r.counts.listed === 1, 'exact record found');
    expect(r.counts.failed === 0, 'no request failed');
    expect(graph.updates.length === 1 && graph.updates[0].id === 'd1', 'the selected node was enriched');
    expect(r.counts.reports > 0, `${r.counts.reports} report campaign(s)`);
    expect(r.counts.related_iocs > 0, `${r.counts.related_iocs} related IOC(s)`);
    const campaign = graph.created.find((n) => n.type === 'threat.campaign');
    if (campaign) console.log(`  sample campaign: ${campaign.data.campaign_name}`);
}

console.log('lookup: an indicator that is not listed');
{
    const graph = memoryGraph({
        d1: { id: 'd1', type: 'infrastructure.domain', data: { domain_name: 'this-domain-is-not-on-lazarus-day.example' } },
    });
    const r = await lookup.run(ctx(graph, { include_related_iocs: false }, ['d1']));
    console.log(`  summary: ${r.summary}`);
    expect(r.counts.not_listed === 1 && r.counts.failed === 0, '404 read as "not listed", not as a failure');
    expect(graph.created.length === 0 && graph.updates.length === 0, 'nothing written for a negative');
}

console.log('lookup: a hash (sha256 → the site’s record)');
{
    const sha256 = '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c';
    const graph = memoryGraph({ h1: { id: 'h1', type: 'threat.file_hash', data: { sha256 } } });
    const r = await lookup.run(ctx(graph, { include_related_iocs: false }, ['h1']));
    console.log(`  summary: ${r.summary}`);
    expect(r.counts.listed === 1, 'hash record found');
    expect(graph.updates[0].data.md5 === 'db349b97c37d22f5ea1d1841e3c89eb4', 'MD5 from the record page');
    expect(r.counts.reports > 0, `${r.counts.reports} report(s)`);
}

console.log('lookup: an IP (ASN + location enrichment)');
{
    const graph = memoryGraph({ i1: { id: 'i1', type: 'infrastructure.ip_address', data: { ip_address: '23.27.13.72' } } });
    const r = await lookup.run(ctx(graph, { include_related_iocs: false }, ['i1']));
    console.log(`  summary: ${r.summary}`);
    expect(r.counts.listed === 1, 'IP record found');
    expect(graph.updates[0].data.asn === 149440, 'ASN written as an integer');
    expect(graph.created.some((n) => n.type === 'infrastructure.autonomous_system'), 'AS node created');
}

console.log('lookup: an ASN (organisation + associated IPs)');
{
    const graph = memoryGraph({ a1: { id: 'a1', type: 'infrastructure.autonomous_system', data: { autonomous_system_number: 149440 } } });
    const r = await lookup.run(ctx(graph, { include_related_iocs: true, max_related_iocs: 5 }, ['a1']));
    console.log(`  summary: ${r.summary}`);
    expect(r.counts.listed === 1, 'ASN record found');
    expect(graph.updates[0].data.autonomous_system_name === 'Evoxt Sdn. Bhd.', 'organisation written onto the ASN');
    expect(graph.created.filter((n) => n.type === 'infrastructure.ip_address').length === 5, 'five related IPs staged');
}

console.log('lookup: a URL (double-encoded record path)');
{
    const graph = memoryGraph({ u1: { id: 'u1', type: 'web.url', data: { url: 'https://cubedesign.co.kr/news' } } });
    const r = await lookup.run(ctx(graph, { include_related_iocs: false }, ['u1']));
    console.log(`  summary: ${r.summary}`);
    expect(r.counts.listed === 1, 'URL record found through the double-encoded path');
}

console.log(bad ? `live-check: ${bad} failure(s)` : 'live-check: all checks passed');
process.exit(bad ? 1 : 0);
