# RFID / NFC Access-Card Security Assessment

**Client:** `<organization>`
**Engagement ID:** `<RFID-YYYY-NNN>`
**Assessment window:** `<start>` → `<end>`
**Tester(s):** `<name / company>`
**Authorization reference:** `<contract / SOW number, signed date>`
**Report version:** `1.0` — `<date>`
**Classification:** `Confidential — Client Only`

---

## 1. Executive summary

Two or three plain-language paragraphs. Answer, for a non-technical reader:

- Can a lost or stolen card be copied by someone who finds it?
- Can a staff member's identity be impersonated with cheap hardware?
- What is the single most urgent fix?

**Overall risk:** `Critical / High / Medium / Low`

| Metric | Value |
|---|---|
| Card models assessed | `<n>` |
| Readers / doors in scope | `<n>` |
| Critical findings | `<n>` |
| High findings | `<n>` |
| Medium findings | `<n>` |
| Low / Info | `<n>` |

---

## 2. Scope

### 2.1 Authorized assets

| # | Asset | Type | Location | Serial / ID | Provided by client |
|---|---|---|---|---|---|
| 1 | `<card model>` | Test card (spare) | `<site>` | `<uid redacted>` | Yes |
| 2 | `<reader model>` | Reader | `<door>` | `<id>` | — |
| 3 | `<controller>` | Backend | `<site>` | `<id>` | — |

### 2.2 Explicitly out of scope

- Cards not listed above, including employee working cards
- Door hardware, controllers, cabling, and lock mechanisms
- Backend credential database
- Denial-of-service or destructive write tests
- Production doors during business hours

### 2.3 Rules of engagement applied

- Bounded key-recovery attempt: `<minutes>` per card, `<>` cards total
- Read-only interrogation of readers
- Test door isolated: `Yes / No`
- Data handling: dumps encrypted at rest, destroyed on acceptance

---

## 3. Methodology

| Phase | Activity | Tooling |
|---|---|---|
| 1 | Technology fingerprint (HF/LF, chip family, SAK/ATQA, UID behaviour) | `pcsc_scan`, `nfc-list`, `proxmark3 hf search`, `hf 14a info` |
| 2 | Default/weak key check on supplied test cards | `hf mf chk`, `mfoc`, `mfcuk` |
| 3 | Data-at-rest review (plaintext, counters, shared keys, access bits) | `cardpeek`, hex inspection |
| 4 | Reader trust-model review (UID-only vs. cryptographic) | Walkthrough with client staff, isolated test door |
| 5 | Risk rating and remediation planning | This document |

Evidence standards: every finding is backed by redacted command output or a
configuration excerpt. No finding is reported from a scanner result alone.

---

## 4. Findings

> Copy one block per finding. Rank by severity, Critical first.
> Redact UIDs, keys, PANs, and employee identifiers — show the pattern, not the secret.

### F-01 — `<title>`

| Field | Value |
|---|---|
| Severity | `Critical` |
| Affected asset | `<card model>` / `<reader>` / `<backend>` |
| CWE / category | `CWE-1393 Use of Default Credentials` / `CWE-294 Authentication Bypass by Capture-replay` |
| Exploited? | `Yes — verified` / `No — theoretical` |

**Description**
What the weakness is, in 2–4 sentences.

**Evidence**
```text
<redacted command output or configuration excerpt>
```

**Impact**
What an attacker physically gains. Be concrete: "opens any door in the
administration wing", "identifies and impersonates employee #----", etc.

**Reproduction (bounded)**
1. `<step>`
2. `<step>`
3. `<expected observation>`

**Remediation**
Specific, testable change. Include effort/owner if known.

**Verification after fix**
How the client can confirm the issue is closed.

---

### F-02 — `<title>`
…

---

## 5. Card / reader inventory detail

| Card model | Chip family | Memory | Crypto | Static UID | Key recovery result |
|---|---|---|---|---|---|
| `<model>` | MIFARE Classic 1K | 16 sectors | Crypto1 | Yes | All sectors from weak keys |
| `<model>` | DESFire EV2 | 4K | AES | Random | Not feasible within limits |

| Reader model | Decision point | Credential check | Notes |
|---|---|---|---|
| `<model>` | Offline (in reader) | UID only | No crypto validation observed |

---

## 6. Risk matrix

| ID | Finding | Likelihood | Impact | Severity | Priority |
|---|---|---|---|---|---|
| F-01 | `<title>` | High | High | Critical | P1 — 7 days |
| F-02 | `<title>` | Medium | High | High | P2 — 30 days |

---

## 7. Remediation roadmap

### Immediate (0–7 days)
- `<action>`

### Short term (1–3 months)
- Replace/upgrade `<readers>` to support secure credentials
- Rotate all site keys; document a key hierarchy

### Strategic (3–12 months)
- Migrate to DESFire EV2/EV3 with AES + per-card diversified keys
- Move authorization decisions to a revocable backend
- Enable anti-passback and failed-auth alerting

### Compensating controls (if migration is slow)
- Personnel-supervised entry at high-value doors
- CCTV coverage and audit-log review
- Immediate revocation process for lost cards

---

## 8. Artifact handling statement

| Artifact | Created | Stored at | Status |
|---|---|---|---|
| `card.dump` (test card 1) | `<date>` | `<encrypted volume>` | Destroyed `<date>` |
| Command logs | `<date>` | `<encrypted volume>` | Retained (redacted copy in report) |

Destruction confirmed by: `<name>` on `<date>`.

---

## 9. Appendix

### A. Glossary
MIFARE Classic, Crypto1, UID, SAK/ATQA, DESFire, secure messaging.

### B. Tool versions
```text
<proxmark3 --version>
<pcsc-tools --version>
<mfoc --version>
```

### C. Evidence index
| Ref | File | Redaction applied |
|---|---|---|
| E-01 | `f01-keycheck.txt` | Keys replaced with `***` |
