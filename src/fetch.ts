// Talking to lazarus.day through the narrowest capability that works.
//
// ONE ENDPOINT, DECLARED IN THE MANIFEST: `https://lazarus.day/iocs`. The host bridge refuses any
// request outside it — compared on the parsed origin and a path-segment boundary, so `/iocs` also
// covers `/iocs/?q=` and `/iocs/<value>/` but not `/iocsomething` and not another host. The
// install gate shows that one line before the analyst approves the pack.
//
// The site sends no `Access-Control-Allow-Origin`, so a plain browser fetch would be unreadable.
// The desktop shell solves that for exactly the origins the open project's installed packs
// declare: `desktop/src/main/net.ts` injects CORS headers for those origins only, in memory, for
// the life of the project (`allowlist.ts` `setPackOrigins`). That is why this pack is desktop-only
// and why it no longer asks for `web_probe` — an arbitrary-host probe was broader than the job,
// which is one site. The endpoint list is the tighter mechanism, and it is the one the install gate
// can actually show.
//
// Requests carry no credential and no headers: `ctx.net.fetch` forces `credentials: "omit"`, and a
// request with nothing to leak may follow a redirect. Redirects on this site stay on the same
// origin (http → https, missing trailing slash); a redirect elsewhere would land on an origin with
// no waiver and be unreadable.
import type { HostContext, SafeResponse } from './sdk';

export const BASE = 'https://lazarus.day';
/** The one origin/path this pack is allowed to reach; mirrored by scopes.network in both plugins. */
export const ENDPOINT = `${BASE}/iocs`;
const RETRY_AFTER_MS = 2_000;

export interface Page {
    /** The URL asked for. The browser may have followed a same-origin redirect. */
    url: string;
    status: number;
    headers: Record<string, string>;
    body: string;
    /** Set when nothing usable came back; `body` is empty then. */
    error?: string;
}

/**
 * The path the site uses for one IOC record.
 *
 * The value is encoded TWICE on purpose: the site's own links are `/iocs/https%253A%252F…/`, and a
 * singly-encoded path answers 404 (measured, not inferred — `https%3A%2F%2F…` 404s while
 * `https%253A%252F…` returns the record). Encoding once more than looks natural reproduces exactly
 * what the site links, for every category including e-mail (`%2540`) and URL.
 */
export function iocPath(value: string): string {
    let segment: string;
    try {
        segment = encodeURIComponent(encodeURIComponent(value));
    } catch {
        // A lone surrogate cannot be encoded; degrade to one pass rather than throw the run.
        segment = encodeURIComponent(value);
    }
    return `/iocs/${segment}/`;
}

export function iocUrl(value: string): string {
    return BASE + iocPath(value);
}

export function searchUrl(query: string, category: string, page: number): string {
    const qs = new URLSearchParams();
    qs.set('q', query);
    if (category && category !== 'all') qs.set('category', category);
    if (page > 1) qs.set('page', String(page));
    return `${BASE}/iocs/?${qs.toString()}`;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve) => {
        if (signal?.aborted) return resolve();
        const done = () => {
            clearTimeout(timer);
            signal?.removeEventListener('abort', done);
            resolve();
        };
        const timer = setTimeout(done, ms);
        signal?.addEventListener('abort', done, { once: true });
    });
}

/**
 * Serial pacing between requests.
 *
 * The site is one researcher's public dataset, not an API with a published quota. 350 ms between
 * requests is deliberately slower than necessary: a run over ten selected nodes finishes in under
 * four seconds, and the site never sees a burst from this pack.
 */
export class Pacer {
    private last = 0;
    constructor(private readonly gapMs = 350) {}

    async wait(signal?: AbortSignal): Promise<void> {
        const delay = this.last + this.gapMs - Date.now();
        if (delay > 0) await sleep(delay, signal);
        this.last = Date.now();
    }
}

function failed(url: string, error: string): Page {
    return { url, status: 0, headers: {}, body: '', error };
}

/**
 * A Cloudflare / DDoS-Guard interstitial is not a 404 and must not be counted as one.
 *
 * Measured on 2026-10-22, lazarus.day answered every request this pack's paths made with 200 (or
 * 404 for an unlisted value) and no challenge; this exists because the failure mode when that
 * changes is the bad one — a challenge page has no `#list-view`, so a parser that ignores it
 * reports "0 IoCs", which reads as a definitive negative about an IOC rather than a blocked
 * request.
 *
 * The generic string "challenge-platform" is deliberately NOT a marker: Cloudflare's bot-detection
 * script is injected at the end of every ordinary page (and lands inside the first 4 KB of the
 * short 404 page), so matching it classified a plain 404 as a bot challenge. Only markers of the
 * challenge itself — its title, its verification form, its `__cf_chl` state object — count.
 */
export function isChallenge(page: Page): boolean {
    if (page.status === 403 || page.status === 503) return true;
    const head = page.body.slice(0, 4096);
    return (
        /<title>\s*Just a moment/i.test(head) ||
        /cf-browser-verification|__cf_chl|_cf_chl_opt/i.test(head) ||
        /Attention Required!|DDoS-Guard/i.test(head)
    );
}

/** One request through the declared endpoint, with one retry for a rate limit or a server error. */
export async function fetchPage(ctx: HostContext, url: string, pacer: Pacer): Promise<Page> {
    await pacer.wait(ctx.signal);
    if (ctx.signal?.aborted) return failed(url, 'cancelled');
    const net = ctx.net;
    if (!net?.fetch) return failed(url, 'network capability not granted');
    const doFetch = net.fetch;

    const once = async (): Promise<Page> => {
        try {
            const res: SafeResponse = await doFetch(url, { method: 'GET' });
            const body = await res.text();
            return { url, status: res.status, headers: res.headers ?? {}, body };
        } catch (e) {
            return failed(url, String(e));
        }
    };

    let page = await once();
    if (page.status === 429 || page.status >= 500) {
        const retryAfter = Number(page.headers['retry-after'] ?? '');
        const wait = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 10_000) : RETRY_AFTER_MS;
        await sleep(wait, ctx.signal);
        if (ctx.signal?.aborted) return failed(url, 'cancelled');
        page = await once();
    }
    return page;
}
