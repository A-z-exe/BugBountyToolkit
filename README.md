# 🛡️ BBT — Bug Bounty Toolkit

A cross-platform security assessment toolkit for testers who need to assess assets
**on an internal / local network first** and **public / hosted sites after**. It runs
fully in pure Python (only `requests` is required) and uses external tools such as
`nmap`, `subfinder`, `whois` or `dig` *optionally* when they are installed.

> ⚠️ **Legal notice** — Use this only against systems you own or are explicitly
> authorized in writing to test, and always stay within the declared scope of a bug
> bounty program. Unauthorized access is illegal. You are responsible for your actions.

---

## ✨ What's new in 2.2

- **BOLA/IDOR checks with two accounts** — replay object endpoints from the
  crawl/OpenAPI spec with a second account (`--header-b` / `--cookie-b`) and
  compare responses. This mirrors the "successful auth ≠ authorized" challenge
  class.
- **SSRF probing (opt-in)** — inject a callback URL you control (`--ssrf-url`)
  and benign internal targets into URL-like parameters, then look for internal
  content or connection errors.
- **WordPress review** — detects WordPress, core/plugin/theme versions, XML-RPC,
  REST user enumeration and upload directory listing.
- **OpenAPI parsing** — machine-readable specs are parsed into
  `api_endpoints.json` and used to build authorization-test candidates.
- New attack-path rules for SSRF, BOLA and WordPress issues.

### From 2.1

- **Same-origin crawler** — discovers links, forms and scripts (bounded by
  `--max-pages` / `--crawl-depth`) and feeds real, parameterised URLs to the
  injection module instead of blasting guessed parameter names.
- **Attack paths** — findings are correlated into short, impact-oriented chains
  (credential disclosure → account takeover, SQLi, CORS data theft, XSS without CSP,
  exposed data stores, …) and each target gets a **risk score (0–100)**.
- **Authenticated scanning** — `-H 'Name: Value'` and `--cookie 'name=value'` are
  applied to every request.
- **Transport check** — detects HTTP-only sites and missing HTTP→HTTPS redirects,
  and groups them with cookie/TLS issues in the attack-path report.
- **Real bug fixes** (details in the changelog at the bottom):
  - public IPs/ranges are no longer misclassified as `local`;
  - `host:port` targets now probe HTTPS *and* HTTP;
  - soft-404 detection also compares Content-Type, so leaked files with a
    coincidentally similar length are not silently dropped;
  - 404/410 responses are never reported as content-discovery "hits";
  - cookie flags are matched case-insensitively (`HTTPOnly`, `httponly`, …);
  - web and API CORS evidence no longer overwrite each other;
  - IPv6 URLs keep their brackets;
  - `--no-optional-tools` is honoured for `nslookup`;
  - `--ports` is validated before a scan starts;
  - silent no-op scans now produce an explicit finding instead of an empty report;
  - outdated TLS 1.0/1.1 support is now actually probed (not just inferred from the
    negotiated version), and TLS inspection is shared between modules.

The crawler also skips GET links that look like logout/session-destroy actions, so
an authenticated scan does not kill its own session.

---

## 🔍 Modules

| Module | What it does |
| --- | --- |
| `info` | DNS resolution / reverse DNS, optional WHOIS + `dig`/`nslookup`, TLS certificate details |
| `network` | Host discovery on a CIDR, TCP port scan, banner grabbing, risky-service flagging, optional nmap |
| `web` | Same-origin crawl, transport (HTTP→HTTPS), security headers, cookie flags, TLS, CORS, HTTP methods, HTML review, soft-404-aware content discovery |
| `wordpress` | WordPress detection, core/plugin/theme versions, XML-RPC, user enumeration, uploads listing |
| `api` | API documentation discovery + OpenAPI parsing, GraphQL introspection check, CORS, JWT analysis |
| `authz` | BOLA/IDOR comparison with a second account (GET only) |
| `ssrf` | Opt-in SSRF probes with callback/internal targets on URL-like parameters |
| `injection` | Reflected XSS, error-based SQLi and open redirect on parameters discovered in the URL/crawl (time-based SQLi only with `--aggressive`) |

Every finding carries a **severity**, **confidence** and enough evidence to verify it
manually. Handled risks are not silently dropped — false positives are expected and
the report says so.

---

## 📋 Requirements

- **Python 3.8+**
- Python package: `requests`

```bash
pip install -r requirements.txt
```

Optional external tools (detected automatically, never required):

| Tool | Adds |
| --- | --- |
| `nmap` | richer service/version detection |
| `subfinder` | passive subdomain discovery |
| `whois` | domain registration data |
| `dig` | detailed DNS records |

`nikto` and `sqlmap` are **not** invoked automatically (they were previously listed
but never wired into the code). Use them manually for deeper testing.

---

## 🔧 Installation

### Any platform / virtualenv (recommended)

```bash
git clone https://github.com/A-z-exe/BugBountyToolkit.git
cd BugBountyToolkit
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
bbt --version
```

### Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nmap whois dnsutils
git clone https://github.com/A-z-exe/BugBountyToolkit.git
cd BugBountyToolkit
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

If your distribution blocks system-wide pip installs (`externally-managed-environment`),
use the venv above or `pipx install .`.

You can always run the historical entry point without installing:

```bash
python bugbounty_tool.py -t https://example.com -m full
```

---

## 🚀 Usage

### Quick start

```bash
# Internal network first
python bugbounty_tool.py -t 192.168.1.0/24 -m network

# Then a hosted site (full assessment + crawl + attack paths)
python bugbounty_tool.py -t https://app.example.com -m full

# Authenticated assessment
python bugbounty_tool.py -t https://app.example.com -m full \
  -H 'Authorization: Bearer eyJ...' --cookie 'session=abc123'

# BOLA/IDOR with two accounts (A = -H/--cookie, B = --header-b/--cookie-b)
bbt -t https://app.example.com -m api \
  -H 'Authorization: Bearer TOKEN_A' \
  --header-b 'Authorization: Bearer TOKEN_B' \
  --authz-id exp_6c2d91

# SSRF with your own callback (Collaborator/webhook)
bbt -t 'https://app.example.com/fetch?url=https://example.com' -m web \
  --ssrf --ssrf-url https://your-collab.oastify.com

# WordPress review (runs inside web/full when WordPress is detected)
bbt -t https://blog.example.com -m web --max-pages 10

# Local web app by hostname, then the public one, in one session
python bugbounty_tool.py -t http://portal.local -t https://portal.example.com -m web --scope auto
```

> Use a target you are authorized to test. A scan of a third-party site without
> permission is illegal even if the tool only sends "safe" requests.

### Interactive mode

```bash
python bugbounty_tool.py
```

### Modes

```bash
python bugbounty_tool.py -t <target> -m info       # DNS / WHOIS / TLS
python bugbounty_tool.py -t <target> -m network    # ports / services
python bugbounty_tool.py -t <target> -m web        # crawl + web assessment
python bugbounty_tool.py -t <target> -m api        # API review
python bugbounty_tool.py -t <target> -m injection  # injection checks
python bugbounty_tool.py -t <target> -m full       # everything (local first)
```

WordPress, SSRF and authz checks run inside `-m web`, `-m api` and `-m full`
(SSRF only when enabled with `--ssrf`/`--ssrf-url`; authz only with a second
account).

### Command line options

| Option | Meaning |
| --- | --- |
| `-t, --target` | Target (URL, host, IP or CIDR). Repeatable. |
| `-f, --targets-file` | File with one target per line. |
| `-m, --mode` | `info`, `network`, `web`, `api`, `injection`, `full`. |
| `--scope` | `auto` (local first), `local`, `remote`. |
| `--scan-network` | Also TCP-scan the host behind each URL target. |
| `--ports` | Port spec, e.g. `22,80,443,8000-8100`. |
| `--threads` | Worker threads for the network module (default 64). |
| `--rate` | HTTP requests/second (default 30, `0` = unlimited). |
| `--timeout` | HTTP timeout in seconds (default 15). |
| `--connect-timeout` | TCP connect timeout (default 3). |
| `--wordlist` | Extra wordlist for content discovery. |
| `--max-paths` | Max paths probed per target (default 400). |
| `--max-hosts` | Max hosts expanded from a CIDR (default 1024). |
| `--max-pages` | Max pages crawled per target (default 25, `0` disables). |
| `--crawl-depth` | Link depth for the crawler (default 2). |
| `--no-crawl` | Disable crawling. |
| `--max-injection-urls` | Crawled parameterised URLs to test (default 10). |
| `--max-injection-params` | Parameters tested per URL (default 6). |
| `-H, --header` | Extra HTTP header `Name: Value` (repeatable). |
| `--cookie` | Cookie(s) `name=value` (repeatable, `;`-separated). |
| `--header-b` / `--cookie-b` | Second-account credentials for BOLA/IDOR comparison. |
| `--authz-id` | Known object ID to test (repeatable, e.g. `exp_6c2d91`). |
| `--max-authz-urls` | Max object URLs tested for BOLA/IDOR (default 15). |
| `--ssrf` | Enable SSRF probes on URL-like parameters. |
| `--ssrf-url` | Callback URL you control (Collaborator/webhook); implies `--ssrf`. |
| `--max-ssrf-urls` | Max parameterised URLs tested for SSRF (default 10). |
| `--jwt` | JWT/bearer token to analyse locally (repeatable). |
| `--proxy` | Proxy URL for HTTP(S) requests. |
| `--verify-tls` | Verify TLS certificates (default off for self-signed internal sites). |
| `--no-optional-tools` | Never call external tools. |
| `--aggressive` | Enable intrusive checks (time-based SQLi). |
| `-o, --output` | Output root directory (default `results`). |
| `--no-color`, `-v` | UI / verbose logging. |
| `--skip-legal` | Skip the legal disclaimer (authorized use only). |

### The local-first workflow

For a target list, BBT classifies each entry as **local** or **remote**:

- private IPs, private CIDRs and hostnames that resolve to private addresses → **local**
- public IPs, public CIDRs and everything else → **remote**

With `--scope auto` (default) local targets are processed first. `--scope local` or
`--scope remote` restricts the run. `--scan-network` adds a port scan of the host
behind each URL.

### What the crawler and injection module actually do

1. The crawler fetches the entry page and up to `--max-pages` same-origin HTML pages,
   following links up to `--crawl-depth`. External origins are never fetched.
2. It extracts links, `<script src>`, forms and form field names. GET forms become
   probe URLs with empty values.
3. `injection` tests parameters that were actually found (target query string +
   crawled URLs), up to `--max-injection-urls` URLs and `--max-injection-params`
   parameters each. If nothing is found it reports that explicitly instead of
   spraying guessed names.

---

## 🧭 Suggested bug-bounty workflow

1. **Read the program scope.** Confirm the domains and asset types you may test.
2. **Run a low-rate pass first:** `-m web --rate 10 --max-pages 15`.
3. **Review `crawl.json`** to see the discovered surface, then test promising
   endpoints manually with Burp/ffuf.
4. **Add authentication** (`-H` / `--cookie`) and re-run so checks hit logged-in pages.
5. **Create a second test account** (`--header-b` / `--cookie-b`) and check
   `authz_results.json`; confirm any BOLA/IDOR lead by hand.
6. **For SSRF**, use a callback you control (`--ssrf-url`) and only then enable
   `--ssrf`; keep metadata probes for `--aggressive`.
7. **Verify every finding manually.** Automated hits are leads, not reports.
8. **Report impact, not scanner output:** the "Attack Paths" section of
   `SECURITY_REPORT.md` is written to help you explain impact and reproduction steps.

---

## 📁 Output structure

```
results/
├── bbt.log                            # debug log for the whole run
└── scan_20260101_120000/
    ├── session_summary.json           # all targets, risk scores + attack paths
    └── http_app.example.com/
        ├── SECURITY_REPORT.md         # human report (attack paths + findings)
        ├── scan_summary.json          # machine-readable findings
        ├── crawl.json                 # pages, links, forms, parameterised URLs
        ├── content_discovery.json     # baseline + hits
        ├── cors_analysis.json
        ├── http_methods.json
        ├── dns_info.json
        ├── tls_certificate.json
        ├── api_cors_analysis.json
        ├── api_docs_discovery.json
        ├── api_spec.json              # raw OpenAPI/Swagger document
        ├── api_endpoints.json         # parsed method/path/parameter list
        ├── authz_results.json         # BOLA/IDOR A-vs-B comparison
        ├── ssrf_results.json          # SSRF probe results
        ├── wordpress.json             # WP version/plugin/theme summary
        ├── network_scan.json
        ├── network_scan.txt
        └── robots.txt
```

---

## 🏗️ Project layout

```
bugbounty_tool.py          # entry point (python bugbounty_tool.py ...)
bbt/
├── cli.py                 # argument parsing + interactive mode
├── core.py                # scanner orchestration, scope classification
├── config.py              # all tunables and limits
├── context.py             # shared state passed to modules
├── findings.py            # Finding model + aggregation
├── target.py              # URL / host / IP / CIDR parsing
├── http_client.py         # requests wrapper (rate limiting, auth headers)
├── checks.py              # reusable web/API checks
├── crawl.py               # bounded same-origin crawler
├── openapi.py             # OpenAPI/Swagger discovery + parsing
├── ids.py                 # object-ID extraction for BOLA/IDOR
├── attack.py              # attack-path correlation + risk score
├── crypto.py              # TLS certificate inspection (stdlib)
├── reporting.py           # Markdown + JSON reports
├── ui.py                  # console output + logging
├── utils.py               # subprocess, sockets, ports, helpers
└── modules/
    ├── base.py            # module interface
    ├── info.py
    ├── network.py
    ├── web.py
    ├── wordpress.py
    ├── api.py
    ├── authz.py
    ├── ssrf.py
    └── injection.py
tests/                     # unit tests (no network required)
legacy/                    # the original v1 script, kept for reference only
```

---

## 🧪 Tests

```bash
python -m pytest tests -q
# or
python -m unittest discover -s tests -v

# lint (optional)
pip install ruff
ruff check bbt tests
```

The tests do not touch the network. They cover target parsing, scope
classification, port specs, CIDR expansion, soft-404 handling, cookie flags,
crawling, OpenAPI parsing, BOLA candidate generation, SSRF probes, WordPress
detection, attack-path correlation, CLI options and finding aggregation.

---

## 🔒 Safety

- Commands are executed **without a shell** (`subprocess` with argument lists), so
  there is no command injection.
- HTTP requests are rate limited and time-bounded; the crawler never leaves the
  target origin.
- Content discovery probes common sensitive files; injection probes send benign
  payloads. Some programs forbid automated scanners entirely — check the rules first.
- Intrusive payloads (time-based SQLi) run only with `--aggressive`.
- BOLA/IDOR checks only send GET requests and never modify objects.
- SSRF probes are opt-in (`--ssrf`/`--ssrf-url`); cloud-metadata payloads are
  gated behind `--aggressive`.
- TLS verification is off by default because internal sites commonly use self-signed
  certificates; enable it with `--verify-tls`.

---

## 🧱 Known limitations

- No JavaScript rendering: links generated only at runtime are not discovered.
- Injection checks target GET parameters discovered by the crawler; POST forms
  (login/signup/contact) must be tested manually or with a proxy.
- Cookies/headers are static; there is no full login-flow or MFA handling.
- TLS protocol support is probed with separate TLS 1.0/1.1 handshakes; whether they
  succeed can depend on the local OpenSSL build’s policy.
- `subfinder` output is saved as an artifact but not automatically scanned.
- BOLA/IDOR checks need two accounts and are heuristic: verify ownership manually.
  Public objects are filtered out, but some false positives remain.
- Blind SSRF requires you to check the callback (`--ssrf-url`); cloud-metadata
  probes only run with `--aggressive`.
- WordPress plugin/theme versions are only detected when readme/style files are
  readable; WPScan remains the better tool for full vulnerability mapping.
- The crawler and web checks are sequential; `--threads` currently affects the
  network module only.
- Attack-path rules are heuristics and require manual verification.

---

## 🗒️ Changelog

### 2.2.0

- Added BOLA/IDOR testing with a second account (`--header-b`, `--cookie-b`,
  `--authz-id`, `--max-authz-urls`). Public objects are filtered with an
  unauthenticated baseline request.
- Added opt-in SSRF probes (`--ssrf`, `--ssrf-url`, `--max-ssrf-urls`).
- Added a WordPress module: detection, core/plugin/theme version comparison,
  XML-RPC, REST user enumeration, author enumeration and uploads listing.
- Added OpenAPI/Swagger parsing (`api_spec.json`, `api_endpoints.json`) and used
  documented paths to build authorization-test candidates.
- Added attack-path rules for SSRF, BOLA and WordPress issues.
- Added `tests/fakes.py` and expanded the suite to 89 tests.

### 2.1.1

- Added an explicit HTTP/HTTPS transport check: HTTP-only sites and missing
  HTTP→HTTPS redirects are now reported (high/medium).
- Attack-path severity is clamped to the strongest supporting finding, so a
  protected `/.env` returning 403 can no longer create a "critical" chain.
- HTTPS/transport findings now join the transport/cookie attack path.
- Test suite expanded to 60 tests.

### 2.1.0

- Added the crawler, attack-path correlation and risk score.
- Added `-H/--header`, `--cookie`, `--max-pages`, `--crawl-depth`, `--no-crawl`,
  `--max-injection-urls`, `--max-injection-params`.
- Injection tests now use discovered parameters instead of guessed names.
- Fixed scope classification for public IPs/CIDRs.
- Fixed `host:port` web detection (HTTPS and HTTP are both tried).
- Fixed soft-404 suppression hiding real files with a similar body length
  (Content-Type is now part of the comparison).
- Fixed 404/410 entries being recorded as content-discovery hits.
- Fixed case-sensitive cookie-flag detection.
- Fixed CORS artifact overwrite between the web and API modules.
- Fixed IPv6 `origin`/`authority` formatting.
- Fixed `--no-optional-tools` being ignored for `nslookup`.
- Fixed `--ports` validation and error messages.
- Silent no-op scans now emit an explicit finding.
- Added `pyproject.toml` (`pip install -e .`, `bbt` command) and 53 unit tests.
- Added active TLS 1.0/1.1 probing and shared TLS inspection between modules.
- The crawler skips logout-style GET links to protect authenticated sessions.
- Windows consoles get ANSI colour enabled when possible.
- README corrected (log location, output tree, crawler, optional tools).

### 2.0.0

- Rewrite as a modular package with pure-Python network scanning, local-first
  ordering, rate limiting, real web/API/injection checks and reports.

---

## ⚖️ License

MIT — see [LICENSE.md](LICENSE.md).

## 👨‍💻 Author

**AmirHossein Zarei (A-z-exe)**

- GitHub: [github.com/a-z-exe](https://github.com/a-z-exe)
- Telegram: [t.me/A_Z_exe](https://t.me/A_Z_exe)
- Instagram: [instagram.com/A_Z_exe](https://instagram.com/A_Z_exe)

---

**⚠️ Remember:** an automated scan is a starting point, not a verdict. Always verify
findings manually, stay inside the program scope, and follow responsible disclosure.
