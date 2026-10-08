# 🛡️ BBT — Bug Bounty Toolkit

A cross-platform security assessment toolkit for testers who need to assess
assets **on an internal / local network first** and **public / hosted sites
after**. It runs fully in pure Python (only `requests` is required) and uses
external tools such as `nmap`, `nikto`, `subfinder` or `sqlmap` *optionally*
when they are installed.

> ⚠️ **Legal notice** — Use this only against systems you own or are explicitly
> authorized in writing to test, and always stay within the declared scope of a
> bug bounty program. Unauthorized access is illegal. You are responsible for
> your actions.

---

## ✨ What's new in v2

This is a rewrite of the original single-file script. Highlights:

- **Cross-platform** — Windows, Linux and macOS. No more `which`/`dig`/`echo |`
  assumptions that only worked on Linux.
- **Modular package** (`bbt/`) instead of one long file.
- **Pure-Python network scanning** (host discovery + TCP port scan + banners)
  so internal networks can be scanned without installing nmap.
- **Local-first workflow** — targets are classified as local/remote and the
  local ones are always tested first.
- **Fixed real bugs** from v1:
  - broken `echo | openssl ...` SSL command (now uses the `ssl` module);
  - `--timeout` was parsed but ignored (now wired everywhere);
  - `netloc` with port broke DNS/SSL commands (now uses `hostname`);
  - SSL command injection / useless input sanitisation removed;
  - failed commands no longer reported as valid output files;
  - `check_requirements` no longer blocks `info` scans because `sqlmap` is
    missing — every module declares its own needs;
  - double output directory creation in `full` mode removed.
- **Real checks** instead of placeholders: proper CORS verdicts, soft-404 aware
  content discovery, cookie flags, HTTP method review, certificate inspection,
  JWT analysis.
- **Rate limiting, timeouts and concurrency** actually implemented.
- **Tests** and a proper `requirements.txt` / `.gitignore`.

---

## 🔍 Modules

| Module | What it does |
|--------|--------------|
| `info` | DNS resolution / reverse DNS, optional WHOIS + `dig`, TLS certificate details |
| `network` | Host discovery on a CIDR, TCP port scan, banner grabbing, risky-service flagging, optional nmap |
| `web` | Security headers, cookie flags, TLS, CORS, HTTP methods, HTML review, soft-404 aware content discovery |
| `api` | API documentation discovery, GraphQL introspection check, CORS, JWT analysis |
| `injection` | Reflected XSS, error-based SQLi, open redirect (time-based SQLi only with `--aggressive`) |

Every finding carries a **severity**, **confidence** and enough evidence to
verify it manually. Handled risks are not silently dropped — false positives are
expected and the report says so.

---

## 📋 Requirements

- **Python 3.8+**
- Python packages:

```bash
pip install -r requirements.txt
```

Optional external tools (detected automatically, never required):

| Tool | Adds |
|------|------|
| `nmap` | richer service/version detection |
| `nikto` | extra web server checks |
| `subfinder` | passive subdomain discovery |
| `whois` | domain registration data |
| `dig` | detailed DNS records |
| `sqlmap` | advanced/manual SQL injection testing |

## 🔧 Installation

```bash
git clone https://github.com/A-z-exe/BugBountyToolkit.git
cd BugBountyToolkit
pip install -r requirements.txt
```

---

## 🚀 Usage

### Quick start

```bash
# Internal network first
python bugbounty_tool.py -t 192.168.1.0/24 -m network

# Then a hosted site
python bugbounty_tool.py -t https://app.example.com -m full

# Local web app by hostname, then the public one, in one session
python bugbounty_tool.py -t http://portal.local -t https://portal.example.com -m web --scope auto
```

### Interactive mode

```bash
python bugbounty_tool.py
```

### Modes

```bash
python bugbounty_tool.py -t <target> -m info       # DNS / WHOIS / TLS
python bugbounty_tool.py -t <target> -m network    # ports / services
python bugbounty_tool.py -t <target> -m web        # web assessment
python bugbounty_tool.py -t <target> -m api        # API review
python bugbounty_tool.py -t <target> -m injection  # injection checks
python bugbounty_tool.py -t <target> -m full       # everything (local first)
```

### Command line options (selection)

```
-t, --target           Target (URL, host, IP or CIDR). Repeatable.
-f, --targets-file     File with one target per line.
-m, --mode             info | network | web | api | injection | full
--scope                auto | local | remote   (auto runs local targets first)
--scan-network         Also port-scan the host behind each URL target
--ports                Port spec, e.g. "22,80,443,8000-8100"
--threads              Worker threads (default 64)
--rate                 HTTP requests/second (default 30, 0 = unlimited)
--timeout              HTTP timeout in seconds (default 15)
--connect-timeout      TCP connect timeout (default 3)
--wordlist             Custom wordlist for content discovery
--jwt                  JWT/bearer token to analyse (repeatable)
--aggressive           Enable intrusive checks (time-based SQLi)
--verify-tls           Verify TLS certificates (default off for self-signed internal sites)
--no-optional-tools    Never call external tools even if installed
--skip-legal           Skip the legal disclaimer (authorized use only)
--no-color / -v        UI / verbose logging
-o, --output           Output root directory (default "results")
```

### The local-first workflow

For a target list, BBT classifies each entry as **local** or **remote**:

- private IPs, CIDRs and hostnames that resolve to private addresses → **local**
- everything else → **remote**

With `--scope auto` (default) the local targets are always processed first, so
you validate the staging/internal deployment before touching the hosted site.
Use `--scope local` or `--scope remote` to restrict a run. `--scan-network`
adds a port scan of the host behind each URL.

---

## 📁 Output structure

```
results/scan_20260101_120000/
├── session_summary.json               # all targets in one machine-readable file
├── bbt.log                            # debug log for the whole run
├── 192.168.1.10_8080/                 # one directory per target
│   ├── SECURITY_REPORT.md
│   ├── scan_summary.json
│   ├── network_scan.json
│   ├── network_scan.txt
│   ├── dns_info.json
│   ├── tls_certificate.json
│   ├── content_discovery.json
│   ├── cors_analysis.json
│   ├── http_methods.json
│   └── api_docs_discovery.json
└── https___app.example.com/
    └── ...
```

---

## 🏗️ Project layout

```
bugbounty_tool.py          # entry point (python bugbounty_tool.py ...)
bbt/
├── cli.py                 # argument parsing + interactive mode
├── core.py                # scanner orchestration, target ordering
├── config.py              # all tunables and limits
├── context.py             # shared state passed to modules
├── findings.py            # Finding model + aggregation
├── target.py              # URL / host / IP / CIDR parsing
├── http_client.py         # requests wrapper (rate limiting, defaults)
├── checks.py              # reusable web/API checks
├── crypto.py              # TLS certificate inspection (stdlib)
├── reporting.py           # Markdown + JSON reports
├── ui.py                  # console output + logging
├── utils.py               # subprocess, sockets, ports, helpers
└── modules/
    ├── base.py            # module interface
    ├── info.py
    ├── network.py
    ├── web.py
    ├── api.py
    └── injection.py
tests/                     # unit tests (no network required)
legacy/                    # the original v1 script, kept for reference
```

---

## 🧪 Tests

```bash
python -m unittest discover -s tests -v
# or
python -m pytest tests
```

The tests do not touch the network; they cover target parsing, port specs,
CIDR expansion and finding aggregation.

---

## 🔒 Safety

- Commands are executed **without a shell** (`subprocess` with argument lists),
  so there is no command injection.
- HTTP requests are rate limited and time-bounded.
- Intrusive payloads (time-based SQLi) run only with `--aggressive`.
- TLS verification is off by default because internal sites commonly use
  self-signed certificates; enable it with `--verify-tls`.

---

## ⚖️ License

MIT — see [LICENSE](LICENSE.md).

## 👨‍💻 Author

**AmirHossein Zarei (A-z-exe)**

- GitHub: [github.com/a-z-exe](https://github.com/a-z-exe)
- Telegram: [t.me/A_Z_exe](https://t.me/A_Z_exe)
- Instagram: [instagram.com/A_Z_exe](https://instagram.com/A_Z_exe)

---

**⚠️ Remember:** an automated scan is a starting point, not a verdict. Always
verify findings manually and follow responsible disclosure.
