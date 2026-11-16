# RFID / NFC Card Security Assessment — Methodology (Authorized Engagements Only)

This document describes how to assess the security of **contactless cards and readers
that the client owns**, under a signed engagement. It is deliberately scoped to
*verification and reporting*, not to producing working clones.

> **Hard rule.** Every card, reader, door, terminal or backend touched must be listed in
> the signed scope. Never test a card belonging to an employee, a visitor, a transit
> operator, a hotel, or any third party. A recovered key or dump is client-confidential
> data and must be handled like a password.

---

## 0. Pre-engagement (do not skip)

Get these in writing before the first command:

| Item | Why |
|---|---|
| Signed authorization / Statement of Work | Legal cover; names the tester, dates, and limits |
| In-scope inventory | Exact card types, reader models, doors/terminals, and their locations |
| Number of test cards | Ask for **spare/unassigned** cards, not an employee's working card |
| Test window and physical access rules | Avoid alarms, business hours, guards |
| Rules of engagement | No denial of service, no tampering with door controllers, no data exfiltration |
| Data handling clause | Where dumps/keys are stored and when they are destroyed |
| Emergency contact | Who to call if a door/terminal misbehaves |
| Reporting format and deadline | Deliverable expectations |

Minimum viable authorization text (adapt, translate, sign):

```text
The Client authorizes <Tester> to perform a security assessment of the contactless
card system described in Annex A between <start> and <end>. The Client confirms it
owns or controls the cards, readers and backend systems in scope and permits
read-only interrogation and key-recovery testing on the supplied test cards.
No denial-of-service, no modification of door controllers, and no production data
may be altered. Findings and any recovered key material are confidential to the
Client and will be destroyed on request.
```

If the client cannot confirm ownership or cannot supply spare cards, **stop**. Testing a
card that a person uses daily can lock them out or destroy data.

---

## 1. Identify what you are dealing with

The card technology decides which tests are even meaningful.

```bash
# ACR122U / PN532 class readers
pcsc_scan                 # reader + ATR, live
nfc-list                  # present cards, UID + type
nfc-scan-device -v        # enumerate devices

# Proxmark3
proxmark3 /dev/ttyACM0
[usb] pm3 --> hf search              # identify HF card family
[usb] pm3 --> hf 14a info            # ISO14443-A: UID, SAK, ATQA, manufacturer
[usb] pm3 --> hf mf info             # MIFARE Classic specifics
```

What the output tells you:

| Observation | Meaning | Security relevance |
|---|---|---|
| SAK `08` / `18` / `88` with 1K/4K | MIFARE Classic | Crypto1 — historically broken; key recovery feasible |
| MIFARE Ultralight / NTAG | No crypto, page-based | UID-only or unprotected data is common |
| DESFire EV1/EV2/EV3 | AES/3DES, secure messaging | Strong if keys are non-default and diversified |
| iCLASS / SEOS / Legic | Proprietary/secure elements | Usually out of reach without vendor tools |
| `ATQA` random per tap | Random UID support | Good sign against UID-only logic |
| Same UID every tap on a "secure" card | Static UID | UID can be trivially replayed by a magic card |

Record: card model, chip family, UID format, memory layout, reader model, and the
credential backend (online validation vs. offline decision in the reader).

---

## 2. Assess credential strength (in-scope test cards only)

### 2.1 Default and weak keys

The realistic finding in most MIFARE Classic deployments is **unchanged factory keys**.

```bash
# Non-destructive key check against known default/weak key lists
[usb] pm3 --> hf mf chk --1k -f keys.lst        # keys.lst: your own list
[usb] pm3 --> hf mf chk --1k --dump               # verify against an existing dump

# Automated key recovery on the client's own card
mfoc -O card.dump                                 # nested attack
mfcuk -C -R 0:A -w 6 -s 250 -S 250 -v 3           # darkside fallback
```

Interpretation for the report:

- **All sectors recovered from a public key list** → Critical. The credential is
  forgeable by anyone with a €20 reader.
- **Some sectors recovered** → High. The remaining keys are the only barrier.
- **None recovered after a bounded attempt** → record as "key recovery not achieved
  within engagement limits"; do not claim the card is secure.

Bound every attempt in the SOW (e.g. "max 30 minutes per card, max 3 cards") so the
test cannot drift into a brute-force campaign.

### 2.2 What is actually stored on the card

Dump analysis, not clone production:

```bash
# Inspect structure and data types
cardpeek card.dump
# or a quick hex/ASCII view of the non-zero blocks
xxd card.dump | head -40
```

Look for, and report as findings:

- PAN/UUID/employee number stored in **plaintext**.
- A **counter or expiry** stored on the card and trusted by the reader (rollback /
  replay possible).
- **Reused keys across all cards** (no per-card diversification).
- **Key A == Key B**, or access bits that leave sectors writable with Key A.
- Card data that the backend never re-validates → offline trust.

### 2.3 Reader-side logic

Confirm with the client's maintenance team or an isolated test door:

- Does the door open on **UID alone** (magic-card replay) or does it validate a
  cryptographic response?
- Is the decision made **in the reader** (offline) or by the controller?
- Is there any **anti-passback / time-of-day** logic, and can it be bypassed by
  replaying a captured transaction?

Proving UID-only trust does **not** require a working clone. A dump plus the reader's
configuration, or a controlled test with the client's own blank magic card **issued and
labelled by the client**, is sufficient evidence.

### 2.4 Relay / range

Only if explicitly in scope and only with the client's own reader and card:

- Range extension (long-range antenna) shows whether distance is a control.
- Relay of a card exchange to a remote reader shows whether the system is
  challenge-response or static.

Both are easy to misread as attacks on real doors — get written confirmation that the
test door is isolated.

---

## 3. Out of scope by default

Do not do these unless separately authorized and physically supervised:

- Cloning a card into circulation or handing a clone to anyone.
- Writing to any block on a production card.
- Opening/tampering with controllers, lock hardware, or cabling.
- Testing cards of people not listed in Annex A.
- Publishing UIDs, keys, dumps, or screenshots that identify a person or a site.

---

## 4. Findings and severity

Use a consistent scale so the client can act on it.

| Severity | Criteria (RFID/NFC) |
|---|---|
| Critical | Full key recovery from default/weak list **and** the credential grants physical access; or plaintext identity data enabling impersonation |
| High | Partial key recovery, or static UID trusted alone, or replayable credential with a bounded window |
| Medium | Undiversified keys across the estate, weak access bits, sensitive-but-not-identifying data in clear |
| Low | Information disclosure with no access impact, missing anti-passback reporting, verbose reader diagnostics |
| Info | Observations, hardening suggestions |

Every finding needs: **evidence** (command output / dump excerpt with data redacted),
**impact** (what an attacker physically gains), **reproduction** (bounded steps), and
**remediation**.

## 5. Remediation guidance to include in the report

- Migrate to **DESFire EV2/EV3 with AES** and per-card diversified keys.
- Never authorize on **UID**; require a cryptographic challenge-response or a signed
  data object.
- Enforce **mutual authentication** and secure messaging on every read.
- Rotate keys on a schedule; keep a documented key hierarchy (master → site → card).
- Move access decisions to a **controller/backend** that can revoke a card instantly.
- Enable anti-passback, time-of-day rules, and alerting on repeated failed auth.
- Label and inventory spare/test cards; retire lost cards immediately.

## 6. Handling of artifacts

- Store dumps/keys encrypted (age/GPG/VeraCrypt), never in the git repo, never in chat.
- Name artifacts by engagement ID, not by employee name.
- Delete working copies after the report is accepted; keep only the redacted evidence
  that appears in the report, and confirm deletion in writing.

---

## 7. Deliverable checklist

- [ ] Authorization and scope annex filed
- [ ] Card and reader inventory table completed
- [ ] Chip family and memory layout documented per card model
- [ ] Key-strength result per card (recovered / partially / not within limits)
- [ ] Data-at-rest analysis with redacted excerpts
- [ ] Reader trust model described (UID-only vs. crypto)
- [ ] Severity table filled with evidence links
- [ ] Remediation roadmap with priorities
- [ ] Artifact destruction confirmation
- [ ] Executive summary in plain language (2–3 paragraphs, no jargon)
