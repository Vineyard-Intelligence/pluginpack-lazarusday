# test-fixtures

Real pages from [lazarus.day](https://lazarus.day/iocs/), captured 2026-10-22 and trimmed to the
sections the parsers read. `<script>` blocks and stylesheet `<link>`s were removed; nothing else was
edited, because the point of these files is to be the markup the regexes were written against.

| File | Page |
| --- | --- |
| `search-blockchain.html` | `/iocs/?q=blockchain` — 27 matches, page 1 (15 rows: e-mails, domains, URLs) |
| `search-empty.html` | `/iocs/?q=zzzznotfoundzzzz` — the no-results page (no list view at all) |
| `detail-domain.html` | `/iocs/blockchain-newtech.com/` — resolved IP, URL on the domain, 5 reports |
| `detail-ip.html` | `/iocs/23.27.13.72/` — country, coordinates, ASN |
| `detail-hash.html` | a WannaCry SHA-256 — MD5/SHA-1/SHA-256, 7 reports |
| `detail-asn.html` | `/iocs/AS149440/` — organisation and 118 associated IPs |
| `detail-email.html` | an e-mail record — Cloudflare-obfuscated `<h2>` |
| `detail-url.html` | `/iocs/https%253A%252F%252Fcubedesign.co.kr%252Fnews/` — double-encoded URL record |
| `not-found.html` | the live 404 page, kept because it carries Cloudflare's JSD script |

The last one is not filler: `not-found.html` contains `challenge-platform` (Cloudflare injects the
bot-detection script into every page, and it lands inside the first 4 KB of this short page). An
earlier challenge detector matched that string and classified every 404 as a bot challenge; the
`src/selftest.ts` case for it is the regression test.

## Licence

These files are trimmed copies of pages from lazarus.day, captured 2026-10-22 for parser tests. The
content is © 2021–2026 lazarusholic, licensed CC BY-SA 4.0
(https://creativecommons.org/licenses/by-sa/4.0/), and is not covered by this repository's
Apache-2.0 licence. See `../NOTICE`.
