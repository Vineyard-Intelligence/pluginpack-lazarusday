// What lazarus.day's HTML says, turned into the small number of facts this pack stages.
//
// Two pages matter:
//
//   * the LIST page (`/iocs/?q=…`) — one `<article>` per IoC in the list view, each with the value,
//     its type, and the first/last-seen dates the site has for it;
//   * the IoC page (`/iocs/<value>/`) — the same record plus its category-specific detail (an IP's
//     ASN, a domain's resolved IPs, a hash's MD5/SHA-1/SHA-256) and the reports that mention it.
//
// Everything here is pure: no ctx, no fetch. That is what makes the fixtures in test-fixtures/
// exercise the same code the pack runs, without a browser or a network.
import type { GraphNode } from './sdk';
import { decodeSegment, textOf } from './html';
import { classifyAddress, eip55, identityFold } from './crypto-address';

export type IocKind = 'domain' | 'ipv4' | 'ipv6' | 'url' | 'hash' | 'email' | 'wallet' | 'asn' | 'unknown';

const KIND_BY_LABEL: Record<string, IocKind> = {
    'IPV4': 'ipv4',
    'IPV4 ADDRESS': 'ipv4',
    'IP ADDRESS': 'ipv4',
    'IPV6': 'ipv6',
    'IPV6 ADDRESS': 'ipv6',
    DOMAIN: 'domain',
    URL: 'url',
    HASH: 'hash',
    EMAIL: 'email',
    WALLET: 'wallet',
    ASN: 'asn',
};

function kindOf(label: string | undefined): IocKind {
    if (!label) return 'unknown';
    return KIND_BY_LABEL[label.replace(/\s+/g, ' ').trim().toUpperCase()] ?? 'unknown';
}

export interface SearchItem {
    kind: IocKind;
    /** The site's own label ("HASH", "IPv4", …), kept for the run log. */
    rawKind: string;
    value: string;
    /** `/iocs/<the site's encoded segment>/`, exactly as linked. */
    path: string;
    firstSeen?: string;
    lastSeen?: string;
}

export interface SearchPage {
    /** The `<p>N IoCs</p>` total for the query, or null when the page did not say. */
    total: number | null;
    items: SearchItem[];
    /** The site answered with its "No IoCs found for …" section. */
    empty: boolean;
}

/**
 * Parse one page of `/iocs/?q=…`.
 *
 * The page renders THREE views of the same fifteen rows (table, list, grid). The table truncates
 * every value to 30 characters with a literal "…" — which is useless for matching — and the list
 * view is the same data untruncated, so that is the section read here. Grid view is cut off so a
 * future change to it cannot silently double every row.
 *
 * The value is taken from the href, not the anchor text, for two reasons: the text is truncated,
 * and Cloudflare replaces every e-mail with an obfuscated `[email protected]` span whose plaintext
 * is only in the href (encoded twice by the site's router). Decoding the segment once recovers the
 * real value for every category.
 */
export function parseSearchPage(html: string): SearchPage {
    const totalMatch = /<p>\s*([\d,]+)\s+IoCs?\s*<\/p>/.exec(html);
    const total = totalMatch ? Number(totalMatch[1].replace(/,/g, '')) : null;
    const empty = /No IoCs found/i.test(html);

    const start = html.indexOf('id="list-view"');
    if (start < 0) return { total, items: [], empty };

    const gridAt = html.indexOf('id="grid-view"', start);
    const block = html.slice(start, gridAt < 0 ? html.length : gridAt);
    const items: SearchItem[] = [];

    const articleRe = /<article>[\s\S]*?<\/article>/g;
    let article: RegExpExecArray | null;
    while ((article = articleRe.exec(block)) !== null) {
        const row = article[0];
        const raw = /href="\/iocs\/([^"]+)"/.exec(row);
        if (!raw) continue;
        // The attribute is `/iocs/<encoded>/`; the final slash is the route separator, not part of
        // the value — a URL IoC that itself ends in "/" still encodes that slash as %252F.
        const segment = raw[1].replace(/\/$/, '');
        const value = decodeSegment(segment);
        if (!value) continue;

        const rawKind = textOf(/<h5>\s*([\s\S]*?)<\/h5>/.exec(row)?.[1] ?? '');
        items.push({
            kind: kindOf(rawKind),
            rawKind,
            value,
            path: `/iocs/${raw[1]}`,
            firstSeen: /First seen:\s*(\d{4}-\d{2}-\d{2})/.exec(row)?.[1],
            lastSeen: /Last seen:\s*(\d{4}-\d{2}-\d{2})/.exec(row)?.[1],
        });
    }

    return { total, items, empty };
}

export interface Report {
    date?: string;
    author?: string;
    title: string;
    /** The lazarus.day report path, e.g. `/reports/<slug>/`. */
    path: string;
    tags: string[];
}

export interface IocDetail {
    kind: IocKind;
    /** The `<h2>` value. Empty for e-mail, where Cloudflare obfuscates it; use the requested value. */
    heading: string;
    md5?: string;
    sha1?: string;
    sha256?: string;
    country?: string;
    latitude?: number;
    longitude?: number;
    asn?: number;
    asnName?: string;
    organization?: string;
    resolvedIps: string[];
    /** URLs the site lists on this domain. */
    urlsOnDomain: string[];
    /** IPs the site lists under this ASN. */
    associatedIps: string[];
    firstSeen?: string;
    lastSeen?: string;
    relatedReports: Report[];
    /** The site's own counters, so a run can say when it saw only part of a list. */
    reportCount: number | null;
    relatedIocCount: number | null;
}

/** `<strong>N</strong>` immediately preceding the given metric label, inside the metrics block. */
function metric(html: string, label: string): number | null {
    const labelAt = html.indexOf(`<p class="label">${label}</p>`);
    if (labelAt < 0) return null;
    // The counter is the nearest `<strong>` BEFORE its own label: the metrics block renders every
    // value before every label, so a forward search from one value finds the next label and reads
    // the previous metric's number.
    const before = html.slice(Math.max(0, labelAt - 400), labelAt);
    const found = [...before.matchAll(/<strong>\s*([\d,]+)\s*<\/strong>/g)];
    if (!found.length) return null;
    return Number(found[found.length - 1][1].replace(/,/g, ''));
}

/** Every `/iocs/…` link inside one `<li>`, decoded back to the value it names. */
function iocLinks(inner: string): string[] {
    const out: string[] = [];
    const re = /href="\/iocs\/([^"]+)"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(inner)) !== null) {
        const value = decodeSegment(m[1].replace(/\/$/, ''));
        if (value && !out.includes(value)) out.push(value);
    }
    return out;
}

const flagEmoji = /[\u{1F1E6}-\u{1F1FF}\u{1F3F4}\u{E0067}-\u{E007F}]/gu;

/**
 * Parse one IoC page.
 *
 * The page is split at the `Related Reports` heading rather than at `</main>`: the details and the
 * metrics sit above it and the timeline below, and a single slice would have to re-derive that
 * boundary from markup that moves. Below the heading, only blocks that actually carry a
 * `/reports/…` link are treated as reports, so the "Back" link and the site's disclaimer at the
 * end of the page cannot become a report.
 */
export function parseDetailPage(html: string): IocDetail {
    const reportsAt = html.indexOf('<h3>Related Reports</h3>');
    const mainAt = html.indexOf('<main class="container">');
    const head = html.slice(mainAt >= 0 ? mainAt : 0, reportsAt >= 0 ? reportsAt : html.length);
    const tail = reportsAt >= 0 ? html.slice(reportsAt) : '';

    const heading = textOf(/<h2>([\s\S]*?)<\/h2>/.exec(head)?.[1] ?? '');
    const rawKind = textOf(/<h3>([\s\S]*?)<\/h3>/.exec(head)?.[1] ?? '');

    const detail: IocDetail = {
        kind: kindOf(rawKind),
        heading: /\[email/i.test(heading) ? '' : heading,
        resolvedIps: [],
        urlsOnDomain: [],
        associatedIps: [],
        relatedReports: [],
        reportCount: metric(head, 'Related Reports'),
        relatedIocCount: metric(head, 'Related IOCs'),
    };

    const liRe = /<li>([\s\S]*?)<\/li>/g;
    let li: RegExpExecArray | null;
    while ((li = liRe.exec(head)) !== null) {
        const inner = li[1];
        const text = textOf(inner);

        const md5 = /MD5:\s*([0-9a-f]{32})/i.exec(text)?.[1];
        if (md5) detail.md5 = md5.toLowerCase();
        const sha1 = /SHA-?1:\s*([0-9a-f]{40})/i.exec(text)?.[1];
        if (sha1) detail.sha1 = sha1.toLowerCase();
        const sha256 = /SHA-?256:\s*([0-9a-f]{64})/i.exec(text)?.[1];
        if (sha256) detail.sha256 = sha256.toLowerCase();

        const country = /Country:\s*(.+)$/.exec(text)?.[1];
        if (country) {
            const clean = country.replace(flagEmoji, '').replace(/\s+/g, ' ').trim();
            if (clean) detail.country = clean;
        }

        const loc = /Location:\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)/.exec(text);
        if (loc) {
            const lat = Number(loc[1]);
            const lng = Number(loc[2]);
            if (Number.isFinite(lat) && Number.isFinite(lng)) {
                detail.latitude = lat;
                detail.longitude = lng;
            }
        }

        // "ASN: AS149440 — Evoxt Sdn. Bhd." The number is parsed on its own so a page that lists the
        // AS without an operator still yields the ASN. The em dash is the site's separator; a
        // hyphen is accepted too, and the name runs to the end of the row.
        const asnNumber = /ASN:\s*AS(\d+)/.exec(text);
        if (asnNumber) detail.asn = Number(asnNumber[1]);
        const asnName = /ASN:\s*AS\d+\s*[—–-]\s*(.+)$/.exec(text)?.[1];
        if (asnName) {
            const name = asnName.trim();
            if (name) detail.asnName = name;
        }

        const org = /Organization:\s*(.+)$/.exec(text)?.[1];
        if (org) detail.organization = org.trim();

        if (/Resolved IPs:/.test(text)) for (const v of iocLinks(inner)) if (!detail.resolvedIps.includes(v)) detail.resolvedIps.push(v);
        if (/URLs on this domain:/.test(text)) for (const v of iocLinks(inner)) if (!detail.urlsOnDomain.includes(v)) detail.urlsOnDomain.push(v);
        if (/Associated IPs:/.test(text)) for (const v of iocLinks(inner)) if (!detail.associatedIps.includes(v)) detail.associatedIps.push(v);

        detail.firstSeen ??= /First Seen:\s*(\d{4}-\d{2}-\d{2})/.exec(text)?.[1];
        detail.lastSeen ??= /Last Seen:\s*(\d{4}-\d{2}-\d{2})/.exec(text)?.[1];
    }

    // A value that is not a date is not a date: `<h2>`-adjacent text and the metrics block share
    // this slice, so the patterns are anchored to their labels rather than to "the first date".
    detail.firstSeen ??= /First Seen:\s*(\d{4}-\d{2}-\d{2})/.exec(textOf(head))?.[1];
    detail.lastSeen ??= /Last Seen:\s*(\d{4}-\d{2}-\d{2})/.exec(textOf(head))?.[1];

    if (tail) {
        const blocks = tail.split('class="timeline-item"');
        for (let i = 1; i < blocks.length; i++) {
            const block = blocks[i];
            const path = /<h4>\s*<a href="(\/reports\/[^"]+)"/.exec(block)?.[1];
            if (!path) continue; // the "Back" link and the disclaimer at the end of the page
            const title = textOf(/<h4>\s*<a href="\/reports\/[^"]+"[^>]*>([\s\S]*?)<\/a>/.exec(block)?.[1] ?? '');
            if (!title) continue;
            const tags: string[] = [];
            const tagRe = /<a href="\/tags\/[^"]+"[^>]*>([\s\S]*?)<\/a>/g;
            let tag: RegExpExecArray | null;
            while ((tag = tagRe.exec(block)) !== null) {
                const t = textOf(tag[1]).replace(/^#/, '').trim();
                if (t && !tags.includes(t)) tags.push(t);
            }
            detail.relatedReports.push({
                date: /\b(\d{4}-\d{2}-\d{2})\b/.exec(block)?.[1],
                author: textOf(/<a href="\/authors\/[^"]+"[^>]*>([\s\S]*?)<\/a>/.exec(block)?.[1] ?? '') || undefined,
                title,
                path,
                tags,
            });
        }
    }

    return detail;
}

/**
 * Reports the site's counter names but the page did not render, per record. Summed per record
 * before records are combined: one report linked from two spellings is rendered on both, so a
 * combined counter would count it twice and call the duplicate "not added".
 */
export function unrenderedReports(detail: IocDetail): number {
    return detail.reportCount != null ? Math.max(0, detail.reportCount - detail.relatedReports.length) : 0;
}

/**
 * Several records of ONE indicator — a wallet the site files under two spellings — as one detail:
 * the earliest first-seen date, the latest last-seen date, every report once (by its path), and the
 * first record's value wherever only one can stand. The counters are dropped; see
 * unrenderedReports.
 */
export function combineDetails(details: IocDetail[]): IocDetail {
    if (details.length === 1) return details[0];
    const dates = (pick: (d: IocDetail) => string | undefined) =>
        details
            .map(pick)
            .filter((d): d is string => !!d)
            .sort();
    const firstSeen = dates((d) => d.firstSeen);
    const lastSeen = dates((d) => d.lastSeen);
    const union = (pick: (d: IocDetail) => string[]) => [...new Set(details.flatMap(pick))];
    const reports: Report[] = [];
    for (const d of details) for (const r of d.relatedReports) if (!reports.some((x) => x.path === r.path)) reports.push(r);
    const first = <K extends keyof IocDetail>(k: K): IocDetail[K] | undefined => details.find((d) => d[k] != null)?.[k];
    // A coordinate pair comes from one record, never one half from each.
    const located = details.find((d) => d.latitude != null && d.longitude != null);
    return {
        kind: details[0].kind,
        heading: details[0].heading,
        md5: first('md5'),
        sha1: first('sha1'),
        sha256: first('sha256'),
        country: first('country'),
        latitude: located?.latitude,
        longitude: located?.longitude,
        asn: first('asn'),
        asnName: first('asnName'),
        organization: first('organization'),
        resolvedIps: union((d) => d.resolvedIps),
        urlsOnDomain: union((d) => d.urlsOnDomain),
        associatedIps: union((d) => d.associatedIps),
        firstSeen: firstSeen[0],
        lastSeen: lastSeen[lastSeen.length - 1],
        relatedReports: reports,
        reportCount: null,
        relatedIocCount: null,
    };
}

// ---- values → node drafts ------------------------------------------------------------------

/** The part of a node draft that is about the IoC itself, before provenance is attached. */
export interface NodeDraft {
    type: string;
    data: Record<string, unknown>;
}

/** The Cryptocurrency pack's address type. The Financial pack's `financial.crypto_address` has no
 *  network and is only read now, never written. */
export const CRYPTO_ADDRESS = 'cryptocurrency.crypto_address';

function hashKind(value: string): 'sha256' | 'sha1' | 'md5' | null {
    const hex = value.trim().toLowerCase();
    if (!/^[0-9a-f]+$/.test(hex)) return null;
    if (hex.length === 64) return 'sha256';
    if (hex.length === 40) return 'sha1';
    if (hex.length === 32) return 'md5';
    return null;
}

/**
 * The graph node one search result becomes, or null for a category this pack cannot model.
 *
 * Concrete types are used wherever one exists — a listed domain is an `infrastructure.domain`, so
 * it de-duplicates against the analyst's existing graph instead of arriving as a second, abstract
 * node. The exception is an MD5/SHA-1-only hash: `threat.file_hash` is identified by its SHA-256
 * (the typepack makes `sha256` required), so a record that only carries the shorter digest has no
 * file-hash node it could legally become. It becomes a `threat.indicator` instead, which is the
 * typepack's own answer for an abstract indicator that has no concrete node yet.
 */
export function nodeForItem(item: SearchItem, url: string): NodeDraft | null {
    const provenance: Record<string, unknown> = { lazarus_day_url: url };
    if (item.firstSeen) provenance.lazarus_day_first_seen = item.firstSeen;
    if (item.lastSeen) provenance.lazarus_day_last_seen = item.lastSeen;

    const value = item.value.trim();
    if (!value) return null;

    switch (item.kind) {
        case 'domain':
            return { type: 'infrastructure.domain', data: { domain_name: value.toLowerCase(), ...provenance } };
        case 'ipv4':
            return { type: 'infrastructure.ip_address', data: { ip_address: value, version: 'ipv4', ...provenance } };
        case 'ipv6':
            return { type: 'infrastructure.ip_address', data: { ip_address: value, version: 'ipv6', ...provenance } };
        case 'url':
            return { type: 'web.url', data: { url: value, ...provenance } };
        case 'email':
            return { type: 'identity.email_address', data: { email: value.toLowerCase(), ...provenance } };
        case 'wallet': {
            // The Cryptocurrency pack's type, identified by (network, address): the site lists
            // values without saying which chain, and the same string is another account on another
            // one. So the network is what the FORMAT settles (bc1…, ltc1…, T…, CashAddr), else
            // `evm` for a 0x address and `unknown` for the rest — what the source said, kept apart
            // from any later judgement about which chain it is on. The address is written in the
            // pack's canonical form (an EVM address in lower case, whatever the site printed).
            const { network, address } = classifyAddress(value);
            return { type: CRYPTO_ADDRESS, data: { network, address, ...provenance } };
        }
        case 'asn': {
            const n = /^AS(\d+)$/i.exec(value)?.[1];
            if (!n) return null;
            const asn = Number(n);
            if (!Number.isInteger(asn) || asn < 0) return null;
            return { type: 'infrastructure.autonomous_system', data: { autonomous_system_number: asn, ...provenance } };
        }
        case 'hash': {
            const lower = value.toLowerCase();
            switch (hashKind(lower)) {
                case 'sha256':
                    return { type: 'threat.file_hash', data: { sha256: lower, ...provenance } };
                case 'sha1':
                    return { type: 'threat.indicator', data: { value: lower, indicator_type: 'sha1', ...provenance } };
                case 'md5':
                    return { type: 'threat.indicator', data: { value: lower, indicator_type: 'md5', ...provenance } };
                default:
                    return { type: 'threat.indicator', data: { value: lower, ...provenance } };
            }
        }
        default:
            return null;
    }
}

/**
 * One wallet the site files under two spellings, as one node.
 *
 * lazarus.day keeps an EVM address checksummed and in lower case as two records, and the type pack
 * folds the two into one node. Written as they came, the second create would set the record URL and
 * dates to whichever row happened to be last, and both rows would be counted as added. So the run
 * merges them itself: the earliest first-seen, the latest last-seen, and the record URL of the row
 * met first (Lookup reads every spelling, whichever URL the node keeps).
 */
export function mergeWalletDraft(prev: Record<string, unknown>, next: Record<string, unknown>): Record<string, unknown> {
    const out = { ...next, ...prev };
    // ISO dates (YYYY-MM-DD) order as strings.
    const pick = (key: string, better: (candidate: string, current: string) => boolean) => {
        const current = typeof prev[key] === 'string' ? (prev[key] as string) : '';
        const candidate = typeof next[key] === 'string' ? (next[key] as string) : '';
        if (candidate && (!current || better(candidate, current))) out[key] = candidate;
    };
    pick('lazarus_day_first_seen', (candidate, current) => candidate < current);
    pick('lazarus_day_last_seen', (candidate, current) => candidate > current);
    return out;
}

/** The identity the Cryptocurrency pack gives a draft: network and folded address (no memo here). */
export const walletKey = (data: Record<string, unknown>) => `${String(data.network)}\0${identityFold(String(data.address ?? ''))}`;

export interface LookupTarget {
    /** Values to try against `/iocs/<value>/`, strongest first. */
    candidates: string[];
    kind: IocKind;
    /**
     * How the candidates relate. false: aliases of ONE record (a file's three digests all reach
     * the same page), so the first that answers is the record. true: each spelling may be a record
     * of its own (a wallet), so every one is read and what they say is combined.
     */
    every: boolean;
}

function str(data: Record<string, unknown>, key: string): string {
    const v = data[key];
    return typeof v === 'string' ? v.trim() : '';
}

/** The value a stored `https://lazarus.day/iocs/<segment>/` names, or '' when it is not one. */
function recordValue(url: string): string {
    const m = /^https:\/\/lazarus\.day\/iocs\/([^/?#]+)\/?(?:[?#].*)?$/.exec(url);
    return m ? decodeSegment(m[1]) : '';
}

/**
 * Every spelling of one crypto address the site may file a record under.
 *
 * The node holds the type pack's canonical form — an EVM address in lower case — but lazarus.day
 * keys a record by the exact string a report printed, and its records are case-sensitive: most EVM
 * wallets are filed checksummed (11 of 13 on the wallet category page, 2026-11-14) and answer 404
 * in lower case, and some addresses are filed BOTH ways, as two records with different reports and
 * dates. Asking for the stored lower-case string alone called a listed wallet "not listed". So the
 * candidates are the spelling the node's own record URL names (what Search found), the value as
 * stored, the EIP-55 spelling and the lower-case one; and a CashAddr also with its prefix, which
 * the type pack drops. A recorded spelling counts only if it folds to the same address, so an
 * edited node cannot send the lookup to someone else's record.
 */
function walletCandidates(data: Record<string, unknown>, address: string, network: string): string[] {
    const out: string[] = [];
    const add = (v: string | null) => {
        if (v && !out.includes(v)) out.push(v);
    };
    const recorded = recordValue(str(data, 'lazarus_day_url'));
    if (recorded && identityFold(recorded) === identityFold(address)) add(recorded);
    add(address);
    if (/^0x[0-9a-fA-F]{40}$/.test(address)) {
        add(eip55(address));
        add(address.toLowerCase());
    }
    if (network === 'bitcoin_cash' && !/^bitcoincash:/i.test(address)) add(`bitcoincash:${address}`);
    return out;
}

/**
 * Which lazarus.day value(s) a selected graph node is looked up by.
 *
 * A File Hash node carries up to three digests and the site may hold any one of them, so all three
 * are candidates in strength order. Everything else maps one-to-one. There is no search involved:
 * `/iocs/<value>/` is an exact record lookup that answers 404 when the site does not list the
 * value, which is both faster and more precise than paging through a substring search.
 */
export function lookupTargets(node: GraphNode): LookupTarget | null {
    const data = (node.data ?? {}) as Record<string, unknown>;
    switch (node.type) {
        case 'infrastructure.domain': {
            const v = str(data, 'domain_name').toLowerCase();
            return v ? { candidates: [v], kind: 'domain', every: false } : null;
        }
        case 'infrastructure.ip_address': {
            const v = str(data, 'ip_address');
            return v ? { candidates: [v], kind: v.includes(':') ? 'ipv6' : 'ipv4', every: false } : null;
        }
        case 'web.url': {
            const v = str(data, 'url');
            return v ? { candidates: [v], kind: 'url', every: false } : null;
        }
        case 'identity.email_address': {
            const v = str(data, 'email').toLowerCase();
            return v ? { candidates: [v], kind: 'email', every: false } : null;
        }
        // Both: nodes this pack wrote before 1.6.0, and anything else written against the Financial
        // pack, are the older type, and are still looked up. Financial 3.0.0 removed that type, so it
        // is no longer in the manifest's `consumes` (lookup.ts); a project keeps its nodes of it.
        case 'financial.crypto_address':
        case CRYPTO_ADDRESS: {
            const v = str(data, 'address');
            return v ? { candidates: walletCandidates(data, v, str(data, 'network')), kind: 'wallet', every: true } : null;
        }
        case 'infrastructure.autonomous_system': {
            const n = data.autonomous_system_number;
            return typeof n === 'number' && Number.isInteger(n) ? { candidates: [`AS${n}`], kind: 'asn', every: false } : null;
        }
        case 'threat.file_hash': {
            const candidates = ['sha256', 'sha1', 'md5']
                .map((k) => str(data, k).toLowerCase())
                .filter((v) => hashKind(v) !== null);
            return candidates.length ? { candidates: [...new Set(candidates)], kind: 'hash', every: false } : null;
        }
        default:
            return null;
    }
}
