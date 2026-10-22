// lazarus.day IOC Search — keyword → the IOC nodes https://lazarus.day lists for it.
//
// This is the site's search box, made into a graph collector. `?q=` is a case-insensitive
// substring match over the stored indicator value only (not report titles or actor names), and the
// results are the site's own records — 15 per page, newest first. Each one becomes the concrete
// node its category names, carrying the record URL and the site's first/last-seen dates, so the
// analyst can pivot from it and can always get back to the page it came from.
//
// WHAT THIS DELIBERATELY DOES NOT DO: it does not invent an anchor node for the query. A search is
// not an entity; a Campaign node named after "blockchain" would be a fabricated thing in the graph
// that every later search would merge into. The results stand as themselves, which is also how the
// Shodan Search plugin ships.
import { definePlugin } from './sdk';
import type { HostContext, RunResult } from './sdk';
import { ENDPOINT, Pacer, fetchPage, isChallenge, searchUrl, withSource } from './fetch';
import { parseSearchPage, parseDetailPage } from './ioc';
import type { NodeDraft, SearchItem } from './ioc';
import { nodeForItem } from './ioc';

// The site also has a browsable `yara` category, but its `?q=` search never matches YARA rule
// names (measured), and no YARA typepack is assumed to be installed. The category is therefore
// not offered; a YARA row that ever does appear is skipped and counted, not silently dropped.
const CATEGORIES = ['all', 'domain', 'ipv4', 'url', 'hash', 'email', 'wallet', 'asn'] as const;
const PAGE_SIZE = 15;
const KIND_LABEL: Record<string, [string, string]> = {
    domain: ['domain', 'domains'],
    ipv4: ['IPv4 address', 'IPv4 addresses'],
    ipv6: ['IPv6 address', 'IPv6 addresses'],
    url: ['URL', 'URLs'],
    hash: ['hash', 'hashes'],
    email: ['e-mail address', 'e-mail addresses'],
    wallet: ['crypto address', 'crypto addresses'],
    asn: ['ASN', 'ASNs'],
};
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** One hash result costs one extra request; a run stops resolving at this many and says so. */
const MAX_HASH_LOOKUPS = 60;

interface HashResolution {
    lookups: number;
    /** Records that were read and simply have no SHA-256 — staged as Indicators, not a failure. */
    noSha256: number;
    /** Record fetches that did not answer (error, challenge, rate limit). */
    unresolved: number;
    /** Records not attempted: the per-run cap, or resolution stopped after a failed fetch. */
    skipped: number;
    stopped: boolean;
}

/**
 * THE LIST SHOWS ONE DIGEST; THE RECORD SHOWS THE FILE.
 *
 * A file-hash record is keyed by its SHA-256, and `?q=<md5>` reaches it through the alias — the
 * search list then shows that SHA-256, while the record page lists the file's MD5, SHA-1 and
 * SHA-256 together. Resolving the record page is what lets the staged node carry all three instead
 * of only the digest the list happened to show. One request per hash result, paced with the rest,
 * capped per run; a failure falls back to the listed digest rather than dropping the result.
 */
async function resolveHashItem(
    ctx: HostContext,
    item: SearchItem,
    url: string,
    pacer: Pacer,
    state: HashResolution,
): Promise<NodeDraft | null> {
    const fallback = nodeForItem(item, url);
    if (state.stopped) {
        state.skipped++;
        return fallback;
    }
    if (state.lookups >= MAX_HASH_LOOKUPS) {
        state.skipped++;
        return fallback;
    }
    state.lookups++;
    const page = await fetchPage(ctx, withSource(url), pacer);
    if (ctx.signal?.aborted) return fallback;
    if (page.error || page.status === 429 || isChallenge(page)) {
        state.unresolved++;
        // A challenge or a rate limit applies to the rest of the run, not just this record.
        state.stopped = true;
        return fallback;
    }
    if (page.status !== 200) {
        state.unresolved++;
        return fallback;
    }
    const detail = parseDetailPage(page.body);
    const listed = item.value.toLowerCase();
    const sha256 = detail.sha256 ?? (/^[0-9a-f]{64}$/.test(listed) ? listed : '');
    if (!sha256) {
        state.noSha256++;
        return fallback;
    }
    const first = item.firstSeen ?? detail.firstSeen;
    const last = item.lastSeen ?? detail.lastSeen;
    return {
        type: 'threat.file_hash',
        data: {
            sha256,
            ...(detail.md5 ? { md5: detail.md5 } : {}),
            ...(detail.sha1 ? { sha1: detail.sha1 } : {}),
            lazarus_day_url: url,
            ...(first ? { lazarus_day_first_seen: first } : {}),
            ...(last ? { lazarus_day_last_seen: last } : {}),
        },
    };
}

export const lazarusSearch = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.lazarusday_search',
        content_type: 'vineyard:plugin',
        name: 'lazarus.day IOC Search',
        version: '1.3.0',
        description:
            'Searches lazarus.day’s public DPRK indicator index by keyword and adds each match as the node its category names — Domain, IP Address, URL, File Hash, E-mail Address, Crypto Address, ASN — carrying the record URL and first/last-seen dates. Matching is a case-insensitive substring of the indicator value. Desktop only.',
        icon: 'radar',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: {
            primary: 'desktop',
            web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
            desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
        },
        io: {
            consumes: [],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'url' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'autonomous_system' },
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'file_hash' },
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'indicator' },
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'email_address' },
                { typepack: 'run.vineyard.typepacks.financial', category: 'financial', name: 'crypto_address' },
            ],
        },
        params: {
            type: 'object',
            properties: {
                query: {
                    type: 'string',
                    title: 'Search query',
                    minLength: 1,
                    description:
                        'Keyword to search the indicator values for, e.g. "blockchain" or "kimsuky". The site matches a case-insensitive substring, so a domain, a hash prefix or a full value all work.',
                },
                category: {
                    type: 'string',
                    title: 'Category',
                    enum: [...CATEGORIES],
                    default: 'all',
                    description: 'Restrict the search to one IOC category. "all" searches every category. Default: all.',
                },
                pages: {
                    type: 'integer',
                    title: 'Pages',
                    minimum: 1,
                    maximum: 10,
                    default: 1,
                    description:
                        'Result pages to read, 15 indicators each, newest first. One page is usually the right answer for a specific keyword; raise it for a broad one. Default: 1 (maximum 10).',
                },
            },
            required: ['query'],
        },
        scopes: {
            graph: ['node:create'],
            // Exactly one endpoint: the site's IOC pages. The host bridge refuses anything else,
            // and the desktop shell waives CORS for this one origin while the pack is installed.
            network: [
                {
                    endpoint: ENDPOINT,
                    methods: ['GET'],
                    purpose: 'Search lazarus.day’s public IOC index by keyword and read the result pages.',
                },
            ],
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },

    async run(ctx: HostContext): Promise<RunResult> {
        if (ctx.run.platform !== 'desktop') {
            return {
                summary:
                    'This plugin only runs in the Vineyard desktop app: lazarus.day sends no CORS headers, so the browser build cannot read its pages. Open the same project in the desktop app to run it.',
                counts: { iocs: 0 },
            };
        }
        if (!ctx.net?.fetch) return { summary: 'Network access was not granted to this plugin', counts: { iocs: 0 } };
        if (!ctx.graph?.createNode) return { summary: 'Graph write access was not granted to this plugin', counts: { iocs: 0 } };

        const query = String(ctx.params?.query ?? '').trim();
        if (!query) return { summary: 'Enter a search keyword, e.g. "blockchain" or "kimsuky".', counts: { iocs: 0 } };

        const asked = String(ctx.params?.category ?? 'all');
        if (asked === 'yara') {
            return {
                summary:
                    'YARA results are not staged yet — this pack covers the site’s other categories. The site’s YARA category is available on the web page.',
                counts: { iocs: 0, skipped_yara: 0 },
            };
        }
        const category = (CATEGORIES as readonly string[]).includes(asked) ? asked : 'all';
        const requested = Math.max(1, Math.min(10, Math.trunc(Number(ctx.params?.pages ?? 1)) || 1));

        const pacer = new Pacer();
        const seen = new Set<string>();
        const byKind: Record<string, number> = {};
        let created = 0;
        let unsupported = 0;
        let blocked = 0;
        let limited = 0;
        let failed = 0;
        let invalid = 0;
        let yaraSkipped = 0;
        const hashState: HashResolution = { lookups: 0, noSha256: 0, unresolved: 0, skipped: 0, stopped: false };
        let pagesRead = 0;
        let total: number | null = null;
        let stopped = false;

        for (let page = 1; page <= requested; page++) {
            if (ctx.signal?.aborted) {
                stopped = true;
                break;
            }
            ctx.progress?.set?.({
                percent: Math.round(((page - 1) / requested) * 100),
                message: `lazarus.day search: "${query}" (page ${page} of ${requested})`,
            });

            const res = await fetchPage(ctx, searchUrl(query, category, page), pacer);
            if (ctx.signal?.aborted) {
                stopped = true;
                break;
            }
            if (res.error) {
                failed++;
                break;
            }
            if (isChallenge(res)) {
                blocked++;
                break;
            }
            if (res.status === 429) {
                // Already retried once by fetchPage. A rate limit is not "no results".
                limited++;
                break;
            }
            // Past the last page the site answers 404 rather than an empty list — that is the end
            // of the results, not a failure.
            if (res.status === 404 && page > 1) break;
            if (res.status !== 200) {
                failed++;
                break;
            }

            const parsed = parseSearchPage(res.body);
            pagesRead++;
            if (parsed.total != null) total = parsed.total;
            if (!parsed.items.length) break;

            for (const item of parsed.items) {
                if (seen.has(item.path)) continue;
                seen.add(item.path);
                if (item.kind === 'unknown' && item.rawKind.toUpperCase() === 'YARA') {
                    // Reached only through `all`. Stated, not silently dropped.
                    yaraSkipped++;
                    continue;
                }
                const url = `https://lazarus.day${item.path}`;
                const draft =
                    item.kind === 'hash' ? await resolveHashItem(ctx, item, url, pacer, hashState) : nodeForItem(item, url);
                if (ctx.signal?.aborted) {
                    stopped = true;
                    break;
                }
                if (!draft) {
                    unsupported++;
                    continue;
                }
                try {
                    await ctx.graph.createNode(draft);
                    created++;
                    byKind[item.kind] = (byKind[item.kind] ?? 0) + 1;
                } catch {
                    // A value the installed typepack's validators refuse must not abort the page.
                    invalid++;
                }
            }

            if (total != null && seen.size >= total) break;
        }

        ctx.progress?.set?.({ percent: 100 });
        if (ctx.signal?.aborted) stopped = true;

        const totalPages = total != null ? Math.max(1, Math.ceil(total / PAGE_SIZE)) : null;
        const parts: string[] = [];
        if (created) {
            const mix = Object.entries(byKind)
                .sort((a, b) => b[1] - a[1])
                .map(([kind, n]) => {
                    const labels = KIND_LABEL[kind];
                    return labels ? plural(n, labels[0], labels[1]) : `${n} ${kind}`;
                })
                .join(', ');
            parts.push(`${stopped ? 'Stopped after' : 'Added'} ${plural(created, 'IoC', 'IoCs')} for "${query}"${mix ? ` (${mix})` : ''}`);
            if (total != null) {
                const coverage = totalPages != null && pagesRead < totalPages ? `, read ${pagesRead} of ${totalPages} pages` : '';
                parts.push(`${plural(total, 'indicator', 'indicators')} ${total === 1 ? 'matches' : 'match'} in total${coverage}`);
            }
            parts.push(
                'lazarus.day labels its IoCs as automatically extracted and warns they may include non-malicious data — treat a hit as “appears in DPRK reporting”, not as a confirmed verdict',
            );
        } else if (stopped) {
            parts.push('Stopped before any result could be read');
        } else if (!blocked && !limited && !failed) {
            parts.push(
                total === 0
                    ? `lazarus.day lists no indicator matching "${query}" — a real negative from the site’s search, not a failed request`
                    : `No indicators were returned for "${query}"`,
            );
        }
        if (yaraSkipped) {
            parts.push(`${plural(yaraSkipped, 'YARA rule result was', 'YARA rule results were')} skipped — YARA is not staged yet`);
        }
        if (unsupported) parts.push(`${plural(unsupported, 'result', 'results')} ${unsupported === 1 ? 'was' : 'were'} a category this pack cannot model`);
        if (invalid) parts.push(`${invalid} value(s) were refused by the installed typepack and skipped`);
        if (hashState.noSha256) {
            parts.push(
                `${plural(hashState.noSha256, 'hash record had', 'hash records had')} no SHA-256 and ${hashState.noSha256 === 1 ? 'was' : 'were'} staged as ${hashState.noSha256 === 1 ? 'an Indicator' : 'Indicators'}`,
            );
        }
        if (hashState.unresolved) {
            parts.push(`${plural(hashState.unresolved, 'hash record', 'hash records')} could not be fetched; the listed digest was used as-is`);
        }
        if (hashState.skipped) {
            parts.push(
                `${plural(hashState.skipped, 'hash record was', 'hash records were')} not resolved (cap ${MAX_HASH_LOOKUPS} per run, or resolution stopped after a failed record fetch)`,
            );
        }
        if (blocked) parts.push('lazarus.day answered with a bot challenge — the search was NOT answered; retry later');
        if (limited) parts.push('lazarus.day rate-limited the search — those pages were NOT answered; wait and retry');
        if (failed) parts.push(`${plural(failed, 'page request', 'page requests')} failed`);
        if (!parts.length) parts.push('Nothing was read');

        return {
            summary: parts.join('. ') + '.',
            counts: {
                iocs: created,
                total: total ?? 0,
                pages: pagesRead,
                domains: byKind.domain ?? 0,
                ip_addresses: (byKind.ipv4 ?? 0) + (byKind.ipv6 ?? 0),
                urls: byKind.url ?? 0,
                hashes: byKind.hash ?? 0,
                emails: byKind.email ?? 0,
                wallets: byKind.wallet ?? 0,
                asns: byKind.asn ?? 0,
                skipped_yara: yaraSkipped,
                unsupported,
                invalid,
                blocked,
                limited,
                failed,
            },
        };
    },
});
