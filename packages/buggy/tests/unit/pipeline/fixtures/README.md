# Pipeline parser fixtures

Every file here is **real output** from the pinned tool version in
`buggy/pipeline/versions.py`, captured on 2026-11-19 and trimmed for size.
Nothing was hand-written except where noted.

| File | Produced by | Target |
|---|---|---|
| `subfinder.jsonl` | `subfinder -d example.com -oJ -cs -silent` (v2.17.0); first 30 lines plus every 800th of 25,527 | passive sources, `example.com` |
| `amass.txt` | `amass enum -passive -d example.com -o ...` (v4.2.0) | passive sources, `example.com` |
| `crtsh.json` | `GET https://crt.sh/?q=%.example.com&output=json`; first 30 of 85 certificates | crt.sh |
| `gau.jsonl` | `gau example.com --json` (v2.2.4); first 60 lines | archive indexes |
| `dnsx.jsonl` | `dnsx -a -aaaa -cname -mx -txt -ns -resp -json -omit-raw` (v1.3.1) | a local dnsmasq serving `lab.test` |
| `naabu.jsonl` | `naabu -json -scan-type c` (v2.7.0) | `localhost` and `127.0.0.1` |
| `httpx.jsonl` | `httpx -json -sc -title -td -server -ip -cname -ct -cl -location -method -tls-grab -irh -ob` (v1.12.0) | OWASP Juice Shop v17.1.1 and a local self-signed TLS server |
| `katana.jsonl` | `katana -jsonl -d 2 -jc -fs fqdn -or -ob` (v1.8.0) | OWASP Juice Shop v17.1.1 |
| `nuclei.jsonl` | `nuclei -jsonl -ni -or -ot` (v3.11.1, templates v10.5.2); the local template path prefix was rewritten to `/opt/nuclei-templates` | OWASP Juice Shop v17.1.1 |
| `gitleaks.json` | `gitleaks dir --report-format json --redact` (v8.30.1) | a directory holding one JS file with planted fake keys |
| `swagger-ui-init.js` | `GET /api-docs/swagger-ui-init.js` | OWASP Juice Shop v17.1.1 |
| `juice_main_excerpt.js` | 12 kB slice of `GET /main.js` | OWASP Juice Shop v17.1.1 |
| `graphql_introspection.json` | introspection `POST /graphql` | Damn Vulnerable GraphQL Application |

Not captured from a live run: **waybackurls**. `web.archive.org` was not
reachable from the capture environment, so `waybackurls` returned nothing. Its
output format is one URL per line; `test_parsers.py` feeds its parser the URL
values from the real `gau.jsonl` (which come from the same archive index) in
that format. Replace this with a captured file when the source is reachable.
