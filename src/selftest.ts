// Self-check for the parsers. Run: npm run selftest
//
// The fixtures under test-fixtures/ are real bytes lifted from lazy day on 2026-10-22 and trimmed
// to the sections the parsers read (scripts and stylesheet links stripped). That is the point of
// this file: a regex that compiles is not a parser that works, and the only way to tell the
// difference is to run it against the markup it was written for.
//
// These run in Node, not the worker: the parsers are pure, so there is no ctx to fake here. Run
// behaviour (network, graph writes, summaries) is exercised separately by test-plugin.mjs.
import { readFileSync } from 'node:fs';
import { iocPath, isChallenge, searchUrl } from './fetch';
import { parseDetailPage, parseSearchPage, nodeForItem, lookupTargets } from './ioc';
import type { SearchItem } from './ioc';

declare const process: { exit(code: number): never };

const fixture = (name: string): string => readFileSync(new URL(`./test-fixtures/${name}`, import.meta.url), 'utf8');

const fail: string[] = [];
const check = (cond: boolean, msg: string) => {
    if (!cond) fail.push(msg);
};
const eq = (actual: unknown, expected: unknown, msg: string) =>
    check(JSON.stringify(actual) === JSON.stringify(expected), `${msg}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

// ---- search page ---------------------------------------------------------------------------
{
    const page = parseSearchPage(fixture('search-blockchain.html'));
    eq(page.total, 27, 'search: total from the IoC counter');
    eq(page.empty, false, 'search: the result page is not the empty page');
    eq(page.items.length, 15, 'search: one item per article, table view not double-counted');

    const [email, domain, url, urlTrailing] = page.items;
    eq(email.kind, 'email', 'search: e-mail row type');
    // Cloudflare replaces the anchor text with an obfuscated span; the href is the only place the
    // address survives, and it is encoded twice.
    eq(email.value, 'blockchainjob2024@outlook.com', 'search: e-mail decoded from the href');
    eq(email.path, '/iocs/blockchainjob2024%2540outlook.com/', 'search: e-mail path kept as the site wrote it');
    eq(email.firstSeen, '2026-09-21', 'search: first-seen date');

    eq(domain.value, 'dennis-blockchain.vercel.app', 'search: domain value');
    eq(domain.kind, 'domain', 'search: domain type');
    eq(url.value, 'https://dennis-blockchain.vercel.app/', 'search: URL value, trailing slash preserved');
    eq(urlTrailing.value.indexOf('https://www.peopleperhour.com/'), 0, 'search: long URL decoded in full');

    check(page.items.every((i) => i.value.length > 0), 'search: no empty values');
    check(page.items.every((i) => i.firstSeen && i.lastSeen), 'search: every row carries both dates');
    check(page.items.every((i) => i.kind !== 'unknown'), 'search: every row mapped to a known category');
}
{
    const page = parseSearchPage(fixture('search-empty.html'));
    eq(page.total, 0, 'empty search: the counter says zero');
    eq(page.empty, true, 'empty search: recognised as the no-results page');
    eq(page.items, [], 'empty search: no items');
}

// ---- IOC pages -----------------------------------------------------------------------------
{
    const d = parseDetailPage(fixture('detail-domain.html'));
    eq(d.kind, 'domain', 'domain: category');
    eq(d.heading, 'blockchain-newtech.com', 'domain: heading');
    eq(d.resolvedIps, ['160.16.200.77'], 'domain: resolved IPs');
    eq(d.urlsOnDomain, ['https://blockchain-newtech.com/download/download.asp'], 'domain: URLs on the domain');
    eq(d.firstSeen, '2023-12-08', 'domain: first seen');
    eq(d.lastSeen, '2024-05-28', 'domain: last seen');
    eq(d.reportCount, 5, 'domain: related-report counter');
    eq(d.relatedIocCount, 2, 'domain: related-IOC counter');
    eq(d.relatedReports.length, 5, 'domain: one report per timeline block');

    const first = d.relatedReports[0];
    eq(first.date, '2024-05-28', 'domain: report date');
    eq(first.author, 'Microsoft', 'domain: report author');
    check(first.title.indexOf('Moonstone Sleet emerges') === 0, 'domain: report title');
    eq(first.path, '/reports/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks-534q5/', 'domain: report path');
    check(first.tags.includes('NPM') && first.tags.includes('MoonstoneSleet'), 'domain: report tags, without the leading #');
    check(d.relatedReports.every((r) => r.path.startsWith('/reports/')), 'domain: every report path is a report');
    check(!d.relatedReports.some((r) => /Back|disclaimer/i.test(r.title)), 'domain: the page footer is not a report');
}
{
    const d = parseDetailPage(fixture('detail-ip.html'));
    eq(d.kind, 'ipv4', 'ip: category');
    eq(d.country, 'United Kingdom', 'ip: country without the flag emoji');
    eq([d.latitude, d.longitude], [51.5092, -0.1189], 'ip: coordinates');
    eq(d.asn, 149440, 'ip: ASN as an integer');
    eq(d.asnName, 'Evoxt Sdn. Bhd.', 'ip: ASN operator');
    eq(d.firstSeen, '2026-10-18', 'ip: first seen');
    eq(d.reportCount, 1, 'ip: related-report counter');
}
{
    const d = parseDetailPage(fixture('detail-hash.html'));
    eq(d.kind, 'hash', 'hash: category');
    eq(d.md5, 'db349b97c37d22f5ea1d1841e3c89eb4', 'hash: MD5');
    eq(d.sha1, 'e889544aff85ffaf8b0d0da705105dee7c97fe26', 'hash: SHA-1');
    eq(d.sha256, '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c', 'hash: SHA-256');
    eq(d.relatedReports.length, 7, 'hash: reports');
}
{
    const d = parseDetailPage(fixture('detail-asn.html'));
    eq(d.kind, 'asn', 'asn: category');
    eq(d.organization, 'Evoxt Sdn. Bhd.', 'asn: organization');
    eq(d.associatedIps.length, 118, 'asn: associated IPs');
    check(d.associatedIps[0] === '193.247.144.38', 'asn: first associated IP');
}
{
    const d = parseDetailPage(fixture('detail-email.html'));
    eq(d.kind, 'email', 'email: category');
    // Cloudflare obfuscates the heading itself here; the caller keeps the value it looked up.
    eq(d.heading, '', 'email: obfuscated heading is not mistaken for the address');
    eq(d.firstSeen, '2026-10-15', 'email: first seen');
    eq(d.relatedReports.length, 1, 'email: reports');
}
{
    const d = parseDetailPage(fixture('detail-url.html'));
    eq(d.kind, 'url', 'url: category');
    eq(d.heading, 'https://cubedesign.co.kr/news', 'url: heading');
    eq(d.relatedReports.length, 1, 'url: reports');
    eq([d.firstSeen, d.lastSeen], ['2026-10-21', '2026-10-21'], 'url: dates');
}

// ---- value → node --------------------------------------------------------------------------
{
    const item = (kind: SearchItem['kind'], value: string): SearchItem => ({ kind, rawKind: kind, value, path: '/iocs/x/' });
    const prov = (draft: ReturnType<typeof nodeForItem> | null) => draft?.data ?? {};

    const domain = nodeForItem(item('domain', 'Evil.Example'), 'https://lazarus.day/iocs/evil.example/');
    eq(domain?.type, 'infrastructure.domain', 'node: domain type');
    eq(prov(domain).domain_name, 'evil.example', 'node: domain lower-cased');
    eq(prov(domain).lazarus_day_url, 'https://lazarus.day/iocs/evil.example/', 'node: provenance URL');

    const ip = nodeForItem(item('ipv4', '1.2.3.4'), 'u');
    eq([ip?.type, prov(ip).version], ['infrastructure.ip_address', 'ipv4'], 'node: IPv4');

    const sha256 = 'a'.repeat(64);
    const hash = nodeForItem(item('hash', sha256), 'u');
    eq([hash?.type, prov(hash).sha256], ['threat.file_hash', sha256], 'node: SHA-256 becomes a File Hash');

    const md5 = nodeForItem(item('hash', 'b'.repeat(32)), 'u');
    eq([md5?.type, prov(md5).indicator_type], ['threat.indicator', 'md5'], 'node: MD5-only becomes an Indicator');

    const asn = nodeForItem(item('asn', 'AS149440'), 'u');
    eq([asn?.type, prov(asn).autonomous_system_number], ['infrastructure.autonomous_system', 149440], 'node: ASN value becomes an integer');

    // YARA is out of scope for now: the row parses (rawKind is kept) but no node is staged.
    eq(
        nodeForItem({ kind: 'unknown', rawKind: 'YARA', value: 'lazarus_relayshell', path: '/iocs/x/' }, 'u'),
        null,
        'node: YARA rules are not staged',
    );

    eq(nodeForItem(item('asn', 'not-an-asn'), 'u'), null, 'node: an unparseable ASN is skipped, not guessed');
}

// ---- lookup targets ------------------------------------------------------------------------
{
    const target = lookupTargets({
        id: 'n1',
        type: 'threat.file_hash',
        data: { sha256: 'C'.repeat(64), sha1: 'd'.repeat(40), md5: 'e'.repeat(32) },
    });
    eq(target?.candidates, ['c'.repeat(64), 'd'.repeat(40), 'e'.repeat(32)], 'lookup: digests tried strongest-first');

    const domain = lookupTargets({ id: 'n2', type: 'infrastructure.domain', data: { domain_name: 'Evil.Example' } });
    eq(domain?.candidates, ['evil.example'], 'lookup: domain lower-cased');

    eq(lookupTargets({ id: 'n3', type: 'threat.malware', data: { name: 'x' } }), null, 'lookup: unsupported type');
    eq(
        lookupTargets({ id: 'n4', type: 'threat.signature', data: { name: 'r', signature_type: 'yara' } }),
        null,
        'lookup: signature nodes are not looked up yet',
    );
}

// ---- URL shapes ----------------------------------------------------------------------------
eq(
    iocPath('https://cubedesign.co.kr/news'),
    '/iocs/https%253A%252F%252Fcubedesign.co.kr%252Fnews/',
    'path: URL is double-encoded, exactly as the site links it',
);
eq(
    iocPath('helpdesk@progressive934.onmicrosoft.com'),
    '/iocs/helpdesk%2540progressive934.onmicrosoft.com/',
    'path: e-mail is double-encoded',
);
eq(iocPath('52fd47ca'), '/iocs/52fd47ca/', 'path: a plain value is unchanged');
eq(
    searchUrl('blockchain', 'domain', 2),
    'https://lazarus.day/iocs/?q=blockchain&category=domain&page=2',
    'search URL: query, category and page',
);
eq(searchUrl('a b', 'all', 1), 'https://lazarus.day/iocs/?q=a+b', 'search URL: space encoded as +, no empty params');

// ---- challenge detection -------------------------------------------------------------------
{
    // The site's 404 page carries Cloudflare's bot-detection script (`challenge-platform` at the
    // end of every page). A generic marker match once classified this as a bot challenge, which
    // turned "not listed" into "blocked" — the exact confusion the run summary exists to avoid.
    const notFound = fixture('not-found.html');
    eq(isChallenge({ url: 'u', status: 404, headers: {}, body: notFound }), false, 'challenge: a real 404 is not a challenge');
    eq(
        isChallenge({ url: 'u', status: 200, headers: {}, body: notFound }),
        false,
        'challenge: a normal page carrying the JSD script is not a challenge',
    );
    eq(
        isChallenge({ url: 'u', status: 403, headers: {}, body: '<title>Just a moment...</title>' }),
        true,
        'challenge: a 403 is a block',
    );
    eq(
        isChallenge({ url: 'u', status: 200, headers: {}, body: '<div id="cf-browser-verification"></div>' }),
        true,
        'challenge: the verification form is a block even with a 200',
    );
}

// ---- report --------------------------------------------------------------------------------
if (fail.length) {
    console.error(`selftest: ${fail.length} failure(s)`);
    for (const f of fail) console.error(`  - ${f}`);
    process.exit(1);
}
console.log('selftest: all checks passed');
