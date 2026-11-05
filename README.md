# 🛡️ BBT — Bug Bounty Toolkit

A cross-platform security assessment toolkit for testers who need to assess assets
**on an internal / local network first** and **public / hosted sites after**. It runs
fully in pure Python (only `requests` is required) and uses external tools such as
`nmap`, `subfinder`, `whois` or `dig` *optionally* when they are installed.

> ⚠️ **Legal notice** — Use this only against systems you own or are explicitly
> authorized in writing to test, and always stay within the declared scope of a bug
> bounty program. Unauthorized access is illegal. You are responsible for your actions.

---

## ✨ What's new in 2.5.1 — searchable desktop launcher

- **BBT in the application menu.** `scripts/install-desktop.sh` installs
  `~/.local/bin/bbt` and a menu entry named *BBT - Bug Bounty Toolkit* with
  `bbt`, *bug bounty*, *recon* and *scan* keywords, so searching for the tool in
  the Kali/XFCE application menu finds and launches it.
- **Useful terminal window.** The menu entry prints `bbt --help` and then opens
  an interactive shell in the project directory with `bbt` already on `PATH`,
  instead of closing immediately.
- The `bbt` console script is available outside the virtualenv as well; run the
  installer once after `pip install -e .`.

## ✨ What's new in 2.5.0 — JavaScript-aware endpoint discovery

- **Katana integration in `-m auto`.** With `--deep`, BBT crawls the target with
  `katana` (JavaScript parsing, depth 2, same-FQDN scope, rate-limited, bounded
  crawl duration) and saves `tools/katana.jsonl`.
- **Notable endpoint summary.** Parameterised, access-controlled (401/403) and
  sensitive-looking paths (`admin`, `api`, `upload`, `debug`, `graphql`, …) are
  summarised in one info finding with evidence lines; everything else stays in
  the JSONL artifact. Results are re-checked against the authorized scope.
- **Bounded by design.** Katana uses `-fs fqdn` so it does not wander onto other
  hosts, `-mdp 150` to cap pages, and `-ct` to stop before the global
  `--command-timeout`. Partial output is kept if the crawl is cut short.

## ✨ What's new in 2.4.0 — autonomous, scope-gated hunts

`-m auto` turns BBT into a one-command orchestrator: give it a URL plus the
program's scope, and it plans and runs the built-in modules **and** the external
tools installed on the machine, then writes one correlated report.

- **Scope gate** — every target, URL and external-tool result is checked against
  a scope file (`--scope-file`) or `--scope-host` entries. Private, loopback,
  link-local and cloud-metadata addresses are refused unless `--allow-private`
  is used in an isolated lab.
- **Adaptive tool plan** — `httpx` and `nuclei` always run; `ffuf`/`nikto`/
  `subfinder` with `--deep`; `wpscan` when WordPress is detected; `sqlmap` only
  with `--aggressive` on a parameterised URL; screenshots with `--screenshots`.
- **Three hard requirements:** `--authorized` (or `--i-have-authorization` /
  `BBT_AUTHORIZED=1`), the legal confirmation, and a resolvable in-scope target.
- **Conservative tool flags:** nuclei excludes intrusive/fuzzing/brute-force/DoS/
  default-login/headless tags and disables interactsh; nikto uses tuning `123b`;
  sqlmap stops after confirming an injection and never dumps data.
- **One report** — `SECURITY_REPORT.md` gains an *Authorized scope* line and an
  *External Tool Runs* table; `hunt_summary.json` records the plan, raw tool runs
  and artifacts. Per-finding bounty drafts still land in `bounty_reports/`.

```bash
printf 'example.com\n*.example.com\n' > scope.txt
bbt -t https://app.example.com -m auto --authorized --scope-file scope.txt --deep
```

## ✨ What's new in 2.3.1

Hardening release focused on scope safety and false positives:

- **TLS verification is on by default.** Use `--insecure` only for self-signed
  internal sites; BBT warns when verification is disabled, especially with
  credentials configured. `--verify-tls` is kept as a no-op for compatibility.
- **Redirects stay on the scanned site.** The HTTP client follows redirects
  manually, rate limits every hop and stops at cross-site hops (exact host or
  `www.` variant only). `resolve_web_entry` also refuses to adopt a cross-host
  final URL.
- **WordPress version comparison fixed** (`1.2` is no longer considered older
  than `1.2.0`).
- **Safer PoC scripts.** Targets are shell-quoted and control characters are
  stripped, so a crafted URL cannot inject commands into a generated PoC.
- **Fewer false positives.** Callback-reflection-only SSRF is reported as
  medium/low confidence, generic takeover markers were removed, and HTTP
  401/403/404 responses are no longer treated as served content in the
  transport check.
- Smaller fixes: version-derived User-Agent, Windows reserved filenames in
  artifacts, wildcard CNAME normalization, a per-page crawler link cap, extra
  database error signatures and report/summary registered as artifacts.

## ✨ What's new in 2.3

- **Bug-bounty report drafts** — every finding gets a Markdown draft with
  reproduction, evidence, impact, remediation and a submission checklist.
- **Safe verification PoCs** — optional shell scripts that replay the minimum
  request (no data dumping, no RCE, no state changes), gated behind
  `--write-pocs --i-have-authorization`.
- **Subdomain-takeover recon** — passive subdomains from crt.sh + DNS, with
  fingerprints for common claimable services (`--subdomain-enum`).
- **JavaScript endpoint extraction** — same-origin bundles are parsed for
  `/api/...` paths and saved as `js_endpoints.json`.
- **Scope warnings** in drafts for classes commonly rejected by programs
  (headers/TLS/version/WordPress).

### From 2.2

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
| `web` | Same-origin crawl, JS endpoint extraction, transport (HTTP→HTTPS), security headers, cookie flags, TLS, CORS, HTTP methods, HTML review, soft-404-aware content discovery |
| `subdomain` | Passive subdomain enumeration (crt.sh + DNS) and takeover fingerprints |
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

For exact CNAME/NS answers during `--subdomain-enum`, install the optional
`dnspython` package (`pip install dnspython`); without it BBT falls back to the
system resolver aliases.

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

### Desktop launcher (application-menu search)

After installing, run once as your desktop user:

```bash
bash scripts/install-desktop.sh
```

This creates `~/.local/bin/bbt` and
`~/.local/share/applications/bbt.desktop`. Search the application menu for
**BBT** or **bug bounty** and the tool appears. If `~/.local/bin` is not on your
`PATH` yet, log out and back in (Kali's `.profile` adds it automatically).

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

# Autonomous hunt: BBT modules + installed external tools, scope-gated
bbt -t https://app.example.com -m auto --authorized --scope-file scope.txt --deep
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
python bugbounty_tool.py -t <target> -m auto --authorized --scope-file scope.txt
```

WordPress, SSRF and authz checks run inside `-m web`, `-m api` and `-m full`
(SSRF only when enabled with `--ssrf`/`--ssrf-url`; authz only with a second
account).

### Autonomous hunt mode (`-m auto`)

`auto` is a **planner on top of the existing modules**, not a separate scanner:

1. Refuses the target unless it is in `--scope-file` / `--scope-host` (or, when
   neither is given, exactly the target host) and resolves to public addresses.
2. Resolves the real HTTP(S) entry point and detects WordPress.
3. Runs the `full` module set, then chooses external tools:
   `httpx` → `nuclei` → (`katana`, `ffuf`, `nikto` with `--deep`) → `wpscan` for
   WordPress → `subfinder` for in-scope subdomains (`--deep`) → `gowitness`
   (`--screenshots`) → `sqlmap` (`--aggressive`, query parameters only).
4. Filters every tool result against the scope again (redirects included), caps
   tool findings with `--max-tool-findings`, and writes the report.

Each external tool is capped by `--command-timeout` (default 300s). `nuclei`
(`-max-time`) and `ffuf` (`-maxtime`) stop gracefully just before that limit and
keep partial results, so a large template set does not wedge the run.

Scope file syntax (one entry per line, `#` comments allowed):

```text
example.com          # apex + all subdomains
*.example.com        # subdomains only
https://app.example.com:8443
203.0.113.10
203.0.113.0/24
```

**It does not exploit anything.** "Exploit" in the output means verification
steps and safe PoCs for a human to review; sqlmap runs in boolean/error mode and
stops at confirmation. Use `--insecure` only for self-signed internal hosts.

### Command line options

| Option | Meaning |
| --- | --- |
| `-t, --target` | Target (URL, host, IP or CIDR). Repeatable. |
| `-f, --targets-file` | File with one target per line. |
| `-m, --mode` | `info`, `network`, `web`, `api`, `injection`, `full`, `auto`. |
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
| `--subdomain-enum` | Passive subdomain enumeration + takeover fingerprints (crt.sh). |
| `--max-subdomains` | Max subdomains resolved (default 200). |
| `--no-js-extract` | Do not parse same-origin JS bundles for API paths. |
| `--no-bounty-reports` | Do not generate per-finding report drafts. |
| `--write-pocs` | Generate safe verification PoC scripts (requires authorization flag). |
| `--i-have-authorization` | Confirm written permission; required for `--write-pocs`/`auto`. |
| `--authorized` | Alias for `--i-have-authorization`; required by `-m auto`. |
| `--scope-file` | Authorized scope file for `-m auto` (host/URL/IP/CIDR per line). |
| `--scope-host` | Authorized host/domain/URL/CIDR for `-m auto` (repeatable). |
| `--deep` | Auto: also run `katana`, `ffuf`, `nikto` and `subfinder` (slower). |
| `--screenshots` | Auto: capture a screenshot with `gowitness` when installed. |
| `--max-tool-findings` | Global cap on findings accepted from external tools (default 200). |
| `--allow-private` | Accept RFC1918/loopback targets (isolated labs only). |
| `--jwt` | JWT/bearer token to analyse locally (repeatable). |
| `--proxy` | Proxy URL for HTTP(S) requests. |
| `--insecure` | Do not verify TLS certificates (self-signed internal sites). |
| `--verify-tls` | Verify TLS certificates (default; kept for compatibility). |
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

A normal scan (`-m web`, `-m full`, …) writes:

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
        ├── js_endpoints.json          # API paths extracted from JS bundles
        ├── subdomains.json            # passive subdomain/CNAME inventory
        ├── authz_results.json         # BOLA/IDOR A-vs-B comparison
        ├── ssrf_results.json          # SSRF probe results
        ├── wordpress.json             # WP version/plugin/theme summary
        ├── bounty_reports/            # per-finding report drafts + safe PoCs
        │   ├── index.md
        │   ├── 01-....md
        │   └── poc-01-....sh
        ├── network_scan.json
        ├── network_scan.txt
        └── robots.txt
```

`-m auto` uses the same layout under `hunt_<stamp>/` and adds:

```
results/hunt_20260101_120000/
├── session_summary.json               # every target, risk score
└── http_app.example.com/
    ├── hunt_summary.json              # plan, tool runs, scope, attack paths
    ├── SECURITY_REPORT.md             # includes scope + external tool table
    └── tools/
        ├── httpx.jsonl                # raw tool output
        ├── nuclei.jsonl
        ├── katana.jsonl
        └── ...
```

---

## 🏗️ Project layout

```
bugbounty_tool.py          # entry point (python bugbounty_tool.py ...)
bbt/
├── cli.py                 # argument parsing + interactive mode
├── core.py                # scanner orchestration, scope classification
├── hunt.py                # autonomous orchestrator for `-m auto`
├── scope.py               # scope policy + private/metadata address guards
├── adapters.py            # external tool adapters, parsers and planner
├── config.py              # all tunables and limits
├── context.py             # shared state passed to modules
├── findings.py            # Finding model + aggregation
├── target.py              # URL / host / IP / CIDR parsing
├── http_client.py         # requests wrapper (rate limiting, auth headers)
├── checks.py              # reusable web/API checks
├── crawl.py               # bounded same-origin crawler
├── openapi.py             # OpenAPI/Swagger discovery + parsing
├── ids.py                 # object-ID extraction for BOLA/IDOR
├── recon.py               # JS endpoint extraction + subdomain takeover recon
├── attack.py              # attack-path correlation + risk score
├── bounty.py              # bounty report drafts + safe verification PoCs
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
    ├── subdomain.py
    └── injection.py
tests/                     # unit tests (no network required)
scripts/
└── install-desktop.sh     # CLI launcher + searchable menu entry
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
detection, subdomain-takeover fingerprints, JS endpoint extraction, bounty
report/PoC generation, attack-path correlation, scope policy, external-tool
parsers, hunt planning, CLI options and findings.

---

## 🔒 Safety

- Commands are executed **without a shell** (`subprocess` with argument lists), so
  there is no command injection.
- Redirects are followed only while they stay on the scanned site; the crawler
  never leaves the target origin.
- TLS certificates are verified by default. `--insecure` disables verification
  for self-signed internal sites and prints a warning (stronger when
  credentials are configured).
- Content discovery probes common sensitive files; injection probes send benign
  payloads. Some programs forbid automated scanners entirely — check the rules first.
- Intrusive payloads (time-based SQLi) run only with `--aggressive`.
- BOLA/IDOR checks only send GET requests and never modify objects.
- SSRF probes are opt-in (`--ssrf`/`--ssrf-url`); cloud-metadata payloads are
  gated behind `--aggressive`.
- Generated PoCs are **verification only**: they replay a benign request and never
  dump data, change state or execute a shell. They require `--i-have-authorization`.
- Subdomain takeover recon never claims a dangling name; it only fingerprints it.
- `-m auto` refuses to start without `--authorized` (or `--i-have-authorization`
  / `BBT_AUTHORIZED=1`) and the legal confirmation. Every target and
  external-tool result is re-checked against the scope; findings outside it are
  dropped. Private, loopback, link-local and cloud-metadata addresses are
  rejected unless you pass `--allow-private` for an isolated lab.
- External tools run with conservative flags: nuclei skips intrusive, fuzzing,
  brute-force, DoS, default-login and headless tags and disables interactsh;
  nikto uses tuning `123b`; sqlmap runs `--smart --technique=BE` and stops after
  confirming injection. BBT does not dump data, escalate privileges, move
  laterally or automate account takeover.
- Reports are drafts for human review; BBT never submits them automatically.

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
- PoC generation is intentionally verification-only; BBT does not automate
  exploitation, data extraction or account takeover.
- Subdomain takeover checks cover common CNAME fingerprints, not every provider.
- Bounty drafts are generic; filter out categories the program rejects.
- `-m auto` needs the external tools on `PATH`; missing tools are reported as
  `skipped` in `hunt_summary.json` and the run continues with the built-ins.
- Auto mode is an orchestrator, not an exploit framework: tool output is parsed
  into findings and re-checked against scope, but nothing is chained into an
  actual compromise. Verify every result manually before submitting.
- Scope matching is domain/host based. A URL entry does not restrict paths, so
  keep the whole host on-program when you declare it.

---

## 🗒️ Changelog

### 2.5.1

- Added `scripts/install-desktop.sh`: installs `~/.local/bin/bbt` and a
  searchable `bbt.desktop` entry (keywords: bbt, bug bounty, recon, scan,
  security) so the tool shows up in the Kali/XFCE application menu.
- The menu entry opens a terminal with `bbt --help` followed by an interactive
  shell in the project directory.

### 2.5.0

- Added a `katana` adapter for JavaScript-aware endpoint discovery, enabled in
  `-m auto --deep`.
- Katana crawls with `-fs fqdn`, depth 2, `-mdp 150` and a crawl-duration cap;
  parser maps JSONL endpoints, keeps only in-scope URLs and produces one info
  finding for notably sensitive or parameterised endpoints.
- Raw crawl output is saved as `tools/katana.jsonl` in the target directory.
- New parser/planner tests; the offline suite now covers 162 tests.

### 2.4.0

- Added `-m auto`: a scope-gated orchestrator that takes a URL (or a target
  file), plans built-in modules plus installed external tools, runs them and
  writes one correlated report.
- New scope model (`bbt/scope.py`): domain/wildcard/URL/IP/CIDR entries, scope
  file parsing, exact-host fallback and guards against private, loopback,
  link-local and cloud-metadata addresses.
- New tool adapters (`bbt/adapters.py`) for httpx, nuclei, ffuf, nikto, wpscan,
  subfinder, gowitness and sqlmap, with parsers, severity mapping and scope
  re-filtering. Intrusive nuclei tags are blocked by default.
- `hunt_summary.json` records the plan, every tool run and its artifacts;
  `SECURITY_REPORT.md` gains *Authorized scope* and *External Tool Runs*
  sections.
- New flags: `--authorized`, `--scope-file`, `--scope-host`, `--deep`,
  `--screenshots`, `--max-tool-findings`, `--allow-private`.
- Auto mode is refused without explicit authorization and clamps the number of
  findings imported from external tools.
- Expanded the offline suite to 160 tests.

### 2.3.1

- Enabled TLS certificate verification by default; added `--insecure` with a
  warning when verification is disabled.
- Pinned redirects to the scanned site (same host or `www.` variant), added a
  per-hop rate limit and a configurable `max_redirects`; cross-host final URLs
  are no longer adopted as the web entry point.
- Fixed WordPress version comparison when segments are omitted (`1.2` vs
  `1.2.0`).
- Shell-quoted PoC targets and stripped control characters to prevent command
  injection in generated scripts; target parsing now rejects control characters.
- Reduced false positives: reflection-only SSRF is medium/low confidence,
  generic takeover markers were removed, and protected/error HTTP endpoints are
  no longer reported as served content.
- Hardening: version-derived User-Agent, Windows reserved filename handling,
  wildcard CNAME normalization, 5,000-link per-page crawler cap, report and
  scan summary registered as artifacts, and more database error signatures.
- Expanded the offline suite to 120 tests.

### 2.3.0

- Added per-finding bounty report drafts (`bounty_reports/`) with reproduction,
  evidence, impact, remediation and a submission checklist.
- Added safe verification PoC scripts (`--write-pocs --i-have-authorization`).
- Added passive subdomain enumeration and takeover fingerprints
  (`--subdomain-enum`, crt.sh + DNS).
- Added same-origin JavaScript endpoint extraction (`js_endpoints.json`).
- Added scope warnings for classes commonly rejected by programs.
- Expanded the offline suite to 101 tests.

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
