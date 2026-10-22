// Talking to lazarus.day, through the only capability that can.
//
// The site sends no `Access-Control-Allow-Origin`, so a browser fetch from the Vineyard web app
// cannot read its HTML — this pack therefore uses `ctx.net.probe` (the desktop shell's anonymous
// main-process fetch) rather than `ctx.net.fetch`, and is declared desktop-only. That is the same
// trade the Ad Tags and Wayback packs make for the same reason.
//
// Three properties of the probe shape this file:
//
//   1. It does NOT follow redirects. lazarus.day answers 301 from http to https and from
//      `/iocs/abcd` to `/iocs/abcd/` (no trailing slash), so a caller that ignores 3xx reads an
//      empty body and calls a listed IOC "not found". Redirects are followed here, by hand.
//   2. The body is capped and may be marked truncated. The pages this pack reads are 20–120 KB;
//      the cap is 1.5 MB and a truncated page is reported as a failure rather than parsed as if
//      complete.
//   3. It is anonymous and quiet. Requests are paced (see Pacer) and a 429 is retried once, so a
//      selection of twenty nodes does not read as a burst.
import type { HostContext, SafeProbeResponse } from './sdk';

export const BASE = 'https://lazarus.day';
/** Far above any page this pack reads (the IOC index is ~90 KB); truncation is still checked. */
export const MAX_BODY_BYTES = 1_500_000;
const MAX_REDIRECTS = 4;
const REQUEST_TIMEOUT_MS = 20_000;
const RETRY_AFTER_MS = 2_000;

export interface Page {
    /** The URL asked for, before redirects. */
    requested: string;
    /** Where the response actually came from. */
    url: string;
    status: number;
    headers: Record<string, string>;
    body: string;
    truncated: boolean;
    error?: string;
    hops: number;
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

function emptyPage(requested: string, error: string): Page {
    return { requested, url: requested, status: 0, headers: {}, body: '', truncated: false, error, hops: 0 };
}

/** One request, following redirects by hand. Never throws. */
export async function probePage(ctx: HostContext, target: string, maxBytes = MAX_BODY_BYTES): Promise<Page> {
    const probe = ctx.net?.probe;
    if (!probe) return emptyPage(target, 'desktop network probe not available');

    let url = target;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
        let res: SafeProbeResponse;
        try {
            res = await probe(url, { method: 'GET', maxBytes, timeoutMs: REQUEST_TIMEOUT_MS });
        } catch (e) {
            return { ...emptyPage(target, String(e)), url, hops: hop };
        }
        if (res.error || res.status === 0) {
            return { ...emptyPage(target, res.error || 'transport error'), url, hops: hop };
        }
        if (res.status >= 300 && res.status < 400 && res.redirectUrl) {
            if (hop === MAX_REDIRECTS) return { ...emptyPage(target, 'redirect loop'), url, hops: hop };
            try {
                url = new URL(res.redirectUrl, url).toString();
            } catch {
                return { ...emptyPage(target, 'unparseable redirect target'), url, hops: hop };
            }
            continue;
        }
        return {
            requested: target,
            url,
            status: res.status,
            headers: res.headers ?? {},
            body: res.body ?? '',
            truncated: !!res.truncated,
            hops: hop,
        };
    }
    return { ...emptyPage(target, 'redirect loop'), url, hops: MAX_REDIRECTS };
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

/** One retry for a rate limit or a transient server error; the caller decides what the final status means. */
export async function fetchPage(
    ctx: HostContext,
    url: string,
    pacer: Pacer,
    maxBytes = MAX_BODY_BYTES,
): Promise<Page> {
    await pacer.wait(ctx.signal);
    if (ctx.signal?.aborted) return emptyPage(url, 'cancelled');
    let page = await probePage(ctx, url, maxBytes);

    if (page.status === 429 || page.status >= 500) {
        const retryAfter = Number(page.headers['retry-after'] ?? '');
        const wait = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 10_000) : RETRY_AFTER_MS;
        await sleep(wait, ctx.signal);
        if (ctx.signal?.aborted) return emptyPage(url, 'cancelled');
        page = await probePage(ctx, url, maxBytes);
    }
    return page;
}
