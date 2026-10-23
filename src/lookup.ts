// lazarus.day IoC Lookup — a selected indicator → its record on https://lazarus.day, the reports that name it,
// and the related indicators the site lists beside it.
//
// The lookup is an EXACT RECORD, not a search: `/iocs/<value>/` answers 200 or 404 for one value,
// so this is a single request per node and a 404 is a real negative ("the site does not list this
// indicator"), never a failed request. That matters more than it sounds — a substring search would
// match a listed `11.2.3.45` for the selected `1.2.3.4` and stage somebody else's record.
//
// WHAT THE SITE ADDS: the IoC index alone is a list of values. The record page is what makes it
// intelligence — the reports (with author, date and tags) that mention the exact value, plus for a
// domain the IPs it resolved to and the URLs on it, for an IP its ASN and location, for a hash the
// other two digests. Those are the facts staged here. Nothing is inferred from a tag or a name.
import { definePlugin } from './sdk';
import type { GraphNode, HostContext, RunResult } from './sdk';
import { BASE, ENDPOINT, Pacer, fetchPage, iocRequestUrl, iocUrl, isChallenge } from './fetch';
import { lookupTargets, parseDetailPage } from './ioc';
import type { IocDetail, Report } from './ioc';

/** A record page shows far fewer than this in practice; the cap is a bound, not an expectation. */
const MAX_REPORTS = 50;
const DEFAULT_RELATED = 50;
const MAX_RELATED = 200;

function asInt(v: unknown, fallback: number): number {
    const n = Math.trunc(Number(v));
    return Number.isFinite(n) ? n : fallback;
}

function isIpv6(value: string): boolean {
    return value.includes(':');
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

function reportDescription(r: Report): string {
    const who = r.author ? `Report by ${r.author}` : 'Report';
    const when = r.date ? `, published ${r.date}` : '';
    const tags = r.tags.length ? ` Tags: ${r.tags.join(', ')}.` : '';
    return `${who}${when}, indexed on lazarus.day.${tags}`;
}

function reportData(r: Report): Record<string, unknown> {
    return {
        campaign_name: r.title,
        description: reportDescription(r),
        ...(r.date ? { start_date: r.date } : {}),
        lazarus_day_url: BASE + r.path,
        ...(r.author ? { lazarus_day_author: r.author } : {}),
        ...(r.tags.length ? { lazarus_day_tags: r.tags.join(', ') } : {}),
    };
}

/** Fields the record page can fill in that the selected node's own type declares. */
function enrichment(node: GraphNode, detail: IocDetail, recordUrl: string): Record<string, unknown> {
    const patch: Record<string, unknown> = { lazarus_day_url: recordUrl };
    if (detail.firstSeen) patch.lazarus_day_first_seen = detail.firstSeen;
    if (detail.lastSeen) patch.lazarus_day_last_seen = detail.lastSeen;

    switch (node.type) {
        case 'infrastructure.ip_address':
            // `asn` is a declared integer on the IP Address type; the rest has no declared home and
            // is carried as clearly-namespaced extras rather than squeezed into `organization`,
            // which may already hold a more specific value from another source.
            if (detail.asn) patch.asn = detail.asn;
            if (detail.asnName) patch.lazarus_day_asn_name = detail.asnName;
            if (detail.country) patch.lazarus_day_country = detail.country;
            if (detail.latitude != null && detail.longitude != null) {
                patch.lazarus_day_location = `${detail.latitude},${detail.longitude}`;
            }
            break;
        case 'threat.file_hash':
            // DELIBERATELY NOT `sha256` — that is the node's identity (and required by the type).
            // Rewriting it would re-key a node the analyst already placed; a sha256 the site knows
            // that the file-hash node did not is recorded as an extra instead.
            if (detail.md5) patch.md5 = detail.md5;
            if (detail.sha1) patch.sha1 = detail.sha1;
            if (detail.sha256 && detail.sha256 !== String((node.data ?? {}).sha256 ?? '').toLowerCase()) {
                patch.lazarus_day_sha256 = detail.sha256;
            }
            break;
        case 'infrastructure.autonomous_system':
            if (detail.organization) patch.autonomous_system_name = detail.organization;
            break;
        default:
            break;
    }
    return patch;
}

export const lazarusLookup = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.lazarusday_lookup',
        content_type: 'vineyard:plugin',
        name: 'lazarus.day IoC Lookup',
        version: '1.4.2',
        description:
            'Looks up each selected Domain, IP Address, URL, File Hash, E-mail Address, Crypto Address or ASN as an exact record in lazarus.day’s public DPRK indicator index, writes the record’s dates and detail onto the node, adds each report that names it as a Campaign linked “reported in”, and optionally adds the IPs and URLs the site lists for a Domain or ASN. Desktop only.',
        icon: 'crosshair',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: {
            primary: 'desktop',
            web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
            desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
        },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'url' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'autonomous_system' },
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'file_hash' },
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'email_address' },
                { typepack: 'run.vineyard.typepacks.financial', category: 'financial', name: 'crypto_address' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'campaign' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'url' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'autonomous_system' },
            ],
        },
        params: {
            type: 'object',
            properties: {
                include_related_iocs: {
                    type: 'boolean',
                    title: 'Also add related IoCs',
                    default: true,
                    description:
                        'For a selected Domain, add the IPs it resolved to and the URLs the site lists on it; for a selected ASN, add the associated IPs. Default: on; off means only the record itself and its reports.',
                },
                max_related_iocs: {
                    type: 'integer',
                    title: 'Related IoC limit',
                    minimum: 1,
                    maximum: MAX_RELATED,
                    default: DEFAULT_RELATED,
                    description:
                        `Most related IoCs to add per selected Domain or ASN. An ASN page can list over a hundred addresses; the run says how many were left out. Default: ${DEFAULT_RELATED} (maximum ${MAX_RELATED}).`,
                },
            },
        },
        scopes: {
            graph: ['node:read', 'node:create', 'node:update', 'edge:create'],
            // Exactly one endpoint: the site's IoC pages. The host bridge refuses anything else,
            // and the desktop shell waives CORS for this one origin while the pack is installed.
            network: [
                {
                    endpoint: ENDPOINT,
                    methods: ['GET'],
                    purpose: 'Read the lazarus.day record page for each selected indicator, including its related reports and IoCs.',
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
                counts: { looked: 0 },
            };
        }
        if (!ctx.net?.fetch) return { summary: 'Network access was not granted to this plugin', counts: { looked: 0 } };
        const graph = ctx.graph;
        if (!graph?.get || !graph.updateNode || !graph.createNode || !graph.createEdge) {
            return { summary: 'Graph read/write access was not granted to this plugin', counts: { looked: 0 } };
        }

        const ids = ctx.input.selection;
        if (!ids.length) {
            return {
                summary: 'Select one or more Domain, IP Address, URL, File Hash, E-mail, Crypto Address or ASN nodes first.',
                counts: { looked: 0 },
            };
        }

        const includeRelated = ctx.params?.include_related_iocs !== false;
        const maxRelated = Math.max(1, Math.min(MAX_RELATED, asInt(ctx.params?.max_related_iocs, DEFAULT_RELATED)));

        const pacer = new Pacer();
        const campaignIds = new Map<string, string>();
        const asnIds = new Map<number, string>();

        let looked = 0;
        let listed = 0;
        let notListed = 0;
        let unsupported = 0;
        let blocked = 0;
        let limited = 0;
        let failed = 0;
        let reportsAdded = 0;
        let reportsDropped = 0;
        let relatedAdded = 0;
        let relatedDropped = 0;
        let invalid = 0;
        let stopped = false;
        const named: string[] = [];

        const reuse = async <K>(cache: Map<K, string>, key: K, make: () => Promise<GraphNode>): Promise<string> => {
            const hit = cache.get(key);
            if (hit) return hit;
            const node = await make();
            cache.set(key, String(node.id));
            return String(node.id);
        };

        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) {
                stopped = true;
                break;
            }
            const node = await graph.get(ids[i]);
            if (!node) {
                unsupported++;
                continue;
            }
            const target = lookupTargets(node);
            if (!target) {
                unsupported++;
                continue;
            }
            looked++;
            ctx.progress?.set?.({
                percent: Math.round((i / ids.length) * 100),
                message: `lazarus.day lookup: ${target.candidates[0] ?? ids[i]} (${i + 1}/${ids.length})`,
            });

            // Try the node's digests strongest-first. A File Hash can hold sha256/sha1/md5 and the
            // site may index any one of them; every other type has exactly one candidate.
            let found: { value: string; detail: IocDetail } | null = null;
            let failedHere = false;
            let blockedHere = false;
            for (const value of target.candidates) {
                if (ctx.signal?.aborted) break;
                const url = iocUrl(value);
                const page = await fetchPage(ctx, iocRequestUrl(value), pacer);
                if (ctx.signal?.aborted) {
                    stopped = true;
                    break;
                }
                if (page.error) {
                    failed++;
                    failedHere = true;
                    break;
                }
                if (isChallenge(page)) {
                    blocked++;
                    blockedHere = true;
                    break;
                }
                if (page.status === 429) {
                    // Already retried once by fetchPage. A rate limit is not "not listed".
                    limited++;
                    failedHere = true;
                    break;
                }
                // 404 is the site's answer for "not in the index" — a real negative, not an error.
                if (page.status === 404) continue;
                if (page.status !== 200) {
                    failed++;
                    failedHere = true;
                    break;
                }
                found = { value, detail: parseDetailPage(page.body) };
                break;
            }
            if (stopped) break;
            if (!found) {
                if (!failedHere && !blockedHere) notListed++;
                continue;
            }
            listed++;
            const detail = found.detail;

            try {
                await graph.updateNode(ids[i], enrichment(node, detail, iocUrl(found.value)));
            } catch {
                // The record is real but this node's installed typepack refused a field (a value
                // that is not an integer ASN, an address that fails the type's regex, …). The
                // reports below are still worth staging; only the enrichment is lost.
                invalid++;
            }

            // The IP's AS becomes a node of its own as well as an `asn` field, matching how the
            // Shodan and IP Recon packs express the same relation ("announced by").
            if (node.type === 'infrastructure.ip_address' && detail.asn) {
                const asn = detail.asn;
                const asnId = await reuse(asnIds, asn, () =>
                    graph.createNode!({
                        type: 'infrastructure.autonomous_system',
                        data: {
                            autonomous_system_number: asn,
                            ...(detail.asnName ? { autonomous_system_name: detail.asnName } : {}),
                        },
                    }),
                );
                await graph.createEdge!({ from: ids[i], to: asnId, label: 'announced by' });
            }

            for (const report of detail.relatedReports) {
                if (reportsAdded >= MAX_REPORTS) {
                    reportsDropped++;
                    continue;
                }
                const campaignId = await reuse(campaignIds, report.title.toLowerCase(), () =>
                    graph.createNode!({ type: 'threat.campaign', data: reportData(report) }),
                );
                await graph.createEdge!({
                    from: ids[i],
                    to: campaignId,
                    label: 'reported in',
                    data: {
                        source: 'lazarus.day',
                        ...(report.date ? { report_date: report.date } : {}),
                        ...(report.author ? { author: report.author } : {}),
                    },
                });
                reportsAdded++;
                if (named.length < 3) {
                    const label = report.title.length > 70 ? `${report.title.slice(0, 69)}…` : report.title;
                    if (!named.includes(label)) named.push(label);
                }
            }
            if (detail.reportCount != null && detail.reportCount > detail.relatedReports.length) {
                reportsDropped += detail.reportCount - detail.relatedReports.length;
            }

            if (includeRelated && (node.type === 'infrastructure.domain' || node.type === 'infrastructure.autonomous_system')) {
                const isDomain = node.type === 'infrastructure.domain';
                const ips = isDomain ? detail.resolvedIps : detail.associatedIps;
                const urls = isDomain ? detail.urlsOnDomain : [];
                const ipLabel = isDomain ? 'resolves to' : 'announces';
                let budget = maxRelated;

                for (const ip of ips) {
                    if (budget <= 0) {
                        relatedDropped++;
                        continue;
                    }
                    try {
                        const ipId = await graph.createNode({
                            type: 'infrastructure.ip_address',
                            data: {
                                ip_address: ip,
                                version: isIpv6(ip) ? 'ipv6' : 'ipv4',
                                lazarus_day_url: iocUrl(ip),
                            },
                        });
                        await graph.createEdge({ from: ids[i], to: String(ipId.id), label: ipLabel, data: { source: 'lazarus.day' } });
                        relatedAdded++;
                    } catch {
                        invalid++;
                    }
                    budget--;
                }
                for (const url of urls) {
                    if (budget <= 0) {
                        relatedDropped++;
                        continue;
                    }
                    try {
                        const urlId = await graph.createNode({
                            type: 'web.url',
                            data: { url, lazarus_day_url: iocUrl(url) },
                        });
                        await graph.createEdge({ from: ids[i], to: String(urlId.id), label: 'hosts', data: { source: 'lazarus.day' } });
                        relatedAdded++;
                    } catch {
                        invalid++;
                    }
                    budget--;
                }
            }
        }

        ctx.progress?.set?.({ percent: 100 });
        if (ctx.signal?.aborted) stopped = true;

        const parts: string[] = [];
        if (listed) {
            parts.push(
                `${stopped ? 'Stopped after' : 'Checked'} ${plural(looked, 'indicator', 'indicators')}: ${listed} listed on lazarus.day` +
                    (named.length ? ` — ${named.join('; ')}` : ''),
            );
            if (reportsAdded) parts.push(`${plural(reportsAdded, 'report', 'reports')} added as Campaigns linked "reported in"`);
            if (relatedAdded) parts.push(`${plural(relatedAdded, 'related IoC', 'related IoCs')} added from the record pages`);
            parts.push(
                'lazarus.day labels its IoCs as automatically extracted and warns they may include non-malicious data — a hit means “appears in DPRK reporting”, not a confirmed verdict',
            );
        } else if (looked === 1) {
            parts.push('The looked-up indicator is not listed on lazarus.day — a negative from the site, not a failed lookup');
        } else if (looked) {
            parts.push(`None of the ${looked} looked-up indicators is listed on lazarus.day — a negative from the site, not a failed lookup`);
        } else {
            parts.push('No selected node was a type this pack can look up');
        }
        if (notListed && listed) parts.push(`${notListed} of the looked-up indicator(s) were not in the index`);
        if (reportsDropped) parts.push(`${plural(reportsDropped, 'report', 'reports')} ${reportsDropped === 1 ? 'was' : 'were'} not added — over the ${MAX_REPORTS}-per-run cap, or the site's counter exceeded the reports it rendered`);
        if (relatedDropped) parts.push(`${plural(relatedDropped, 'related IoC', 'related IoCs')} ${relatedDropped === 1 ? 'was' : 'were'} left out (limit ${maxRelated})`);
        if (unsupported) parts.push(`${plural(unsupported, 'selected node is', 'selected nodes are')} a type this pack does not look up`);
        if (invalid) parts.push(`${plural(invalid, 'value was', 'values were')} refused by the installed typepack and skipped`);
        if (blocked) parts.push('lazarus.day answered with a bot challenge — those lookups were NOT answered; retry later');
        if (limited) parts.push('lazarus.day rate-limited those lookups — they were NOT answered; wait and retry');
        if (failed) parts.push(`${failed} lookup(s) failed`);

        return {
            summary: parts.join('. ') + '.',
            counts: {
                looked,
                listed,
                not_listed: notListed,
                reports: reportsAdded,
                related_iocs: relatedAdded,
                unsupported,
                blocked,
                limited,
                failed,
                reports_dropped: reportsDropped,
                related_dropped: relatedDropped,
                invalid,
            },
        };
    },
});
