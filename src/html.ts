// The small amount of HTML handling this pack needs, kept in one place because every parser here
// works on raw strings: a plugin runs in a Web Worker with no DOM, so `document`/`DOMParser` are
// not available and a regex is the only tool there is.
//
// This is not a general HTML parser and must not become one. It is written against the exact
// markup lazarus.day servers (see test-fixtures/, which is real bytes), and the tests fail if the
// shapes it assumes change. Where a regex could plausibly over-match (the timeline blocks, the
// `<li>` rows), the caller bounds the slice first.

const NAMED: Record<string, string> = {
    amp: '&',
    lt: '<',
    gt: '>',
    quot: '"',
    apos: "'",
    nbsp: ' ',
    laquo: '\u00ab',
    raquo: '\u00bb',
    mdash: '\u2014',
    ndash: '\u2013',
    hellip: '\u2026',
    middot: '\u00b7',
    bull: '\u2022',
    lsquo: '\u2018',
    rsquo: '\u2019',
    ldquo: '\u201c',
    rdquo: '\u201d',
    copy: '\u00a9',
    reg: '\u00ae',
};

/**
 * Decode the entities the site actually emits.
 *
 * Report titles and authors are free text and are the place this matters: "Q&A: ..." arrives as
 * `Q&amp;A`, and storing the raw entity would make two spellings of one campaign name and split
 * the node. Numeric entities are handled too because the markup uses `&#160;` inside the
 * Cloudflare-obfuscated e-mail span.
 */
export function decodeEntities(s: string): string {
    if (!s || s.indexOf('&') < 0) return s;
    return s
        .replace(/&#x([0-9a-f]+);/gi, (_, hex: string) => safeCodePoint(parseInt(hex, 16)))
        .replace(/&#(\d+);/g, (_, dec: string) => safeCodePoint(parseInt(dec, 10)))
        .replace(/&([a-z][a-z0-9]*);/gi, (whole, name: string) => NAMED[name.toLowerCase()] ?? whole);
}

function safeCodePoint(n: number): string {
    if (!Number.isFinite(n) || n < 0 || n > 0x10ffff) return '';
    try {
        return String.fromCodePoint(n);
    } catch {
        return '';
    }
}

/** Tags out, entities decoded, whitespace collapsed. */
export function textOf(html: string): string {
    return decodeEntities(html.replace(/<[^>]*>/g, ' '))
        .replace(/\s+/g, ' ')
        .trim();
}

/**
 * A URL path segment the site wrote for an IoC, decoded back to the value it names.
 *
 * TWICE, because that is how the site encodes: an IoC value of `https://x/a` is linked as
 * `/iocs/https%253A%252F%252Fx%252Fa/`, and `/iocs/helpdesk%2540…/` for an e-mail. One decode
 * leaves `%3A` and `%40` (`https%3A%2F%2F…`), which is the site's stored form, not the value. A
 * value that itself contains a percent-escape survives the round trip: `%20` becomes `%2520` and
 * back. If a segment is ever singly encoded, the second decode throws on the intermediate string
 * and the fallback decodes once.
 */
export function decodeSegment(segment: string): string {
    try {
        return decodeURIComponent(decodeURIComponent(segment));
    } catch {
        try {
            return decodeURIComponent(segment);
        } catch {
            return segment;
        }
    }
}
