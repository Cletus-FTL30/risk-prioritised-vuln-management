# Stage 3: Extraction, Normalisation and Enrichment

## Objective

Turn raw scanner output into a dataset that can be reasoned about, then enrich it with live
exploit intelligence from public sources.

Stages 1 and 2 produced findings in a tool's native format, read through a tool's own interface.
This stage extracts them programmatically, normalises them into a consistent shape, and adds
data the scanner does not provide, so that prioritisation can be built on something other than
the severity label the scanner assigned.

**Result:** 623 findings across five scan runs, referencing 808 distinct CVEs, enriched against
FIRST EPSS and the CISA Known Exploited Vulnerabilities catalogue.

---

## Why extraction was not straightforward

Bulk export is restricted on the scanner licence in use, so the dataset was assembled from the
REST API's read endpoints. That worked, but the data arrives spread across three places that do
not agree with each other.

| Source | Contains | Coverage |
|---|---|---|
| `vulnerabilities[]` | plugin id, name, family, severity, instance count | every finding |
| `prioritization.plugins[]` | CVEs, CVSS, VPR drivers, host mapping | a small fraction |
| `plugins/<id>.json` | per-plugin detail, captured separately | every plugin |

The first version of the parser iterated `prioritization`, because it was the richest structure.
It produced 10 findings and reported 100% signal coverage, which looked like success.

It was not. The `prioritization` block covers 10 plugins out of 369 on the largest scan, and
zero on three of the five runs. Those 10 were the best-documented records in the dataset, not a
sample of it.

Inverting the design fixed it: `vulnerabilities` is the source of truth for what was found, and
the other two are enrichment layered on top by plugin id. The output went from 10 findings to
623.

---

## Three failures that produced no error

Every data problem in this stage was silent. Nothing raised an exception, nothing logged a
warning, and every intermediate result looked plausible.

### A cancelled scan returned as current

The baseline Metasploitable scan came back with zero vulnerabilities. The file parsed cleanly
and the API returned HTTP 200.

Querying the scan's history explained it:

```
history_id 6   completed
history_id 12  canceled
```

The endpoint returns the most recent run by default, and the most recent run had been cancelled.
A cancelled scan is an empty scan, and an empty scan is indistinguishable from a clean one
unless you check why.

### The wrong run for the AWS host

The same default cost more. The AWS credentialed scan had four runs: the one carrying 21
Critical and High findings, and three others including the clean post-remediation scan. The API
returned the latest, which was the clean one.

The dataset would have contained a cloud host with no findings, and Stage 2's central result
would have been unsupported by the data behind it.

Both were resolved by requesting runs explicitly with `history_id`, and by capturing the AWS
scan twice, before and after remediation, so that later stages have a real delta to work with.

### A string that was not a boolean

The field marking whether a scan was authenticated arrives as the string `"false"`, not a
boolean. In Python, any non-empty string is truthy, so:

```python
any(h.get("credential") for h in hosts)   # True for every scan
```

Every finding in the dataset was labelled as coming from an authenticated scan, including both
unauthenticated baselines. The credentialed versus uncredentialed comparison that is the
headline of Stages 1 and 2 would have been unprovable from the data supporting it, and nothing
in the output would have indicated a problem.

### The pattern

Three failures, all silent, all producing output that looked correct. This mirrors Stage 2,
where a host had patched itself between scan and verification without either the scan or the
verification being wrong.

The practical conclusion for the rest of this project is that correctness has to be asserted
rather than assumed. The parser prints a coverage report on every run for that reason: not as a
diagnostic, but because a dataset that silently loses 98% of its records otherwise looks exactly
like one that did not.

---

## Dataset

Five runs, captured by explicit history id:

| Run | Findings | Authenticated |
|---|---|---|
| Metasploitable, baseline | 109 | no |
| Metasploitable, credentialed | 369 | yes |
| AWS Ubuntu, baseline | 12 | no |
| AWS Ubuntu, credentialed, pre-remediation | 81 | yes |
| AWS Ubuntu, credentialed, post-remediation | 52 | yes |
| **Total** | **623** | |

These counts are higher than the interface displays, because the interface collapses related
findings into grouped rows such as "SSL (Multiple Issues)". The API returns them individually.
Any metric drawn from the two sources will disagree unless the grouping behaviour is accounted
for.

### Severity distribution

| Severity | Count |
|---|---|
| Critical | 37 |
| High | 112 |
| Medium | 152 |
| Low | 24 |
| Informational | 298 |

---

## Signal coverage

The parser reports how many findings carry each field. This is the central output of the stage,
because it determines what a scoring model can actually be built on.

| Signal | Present | Coverage |
|---|---|---|
| Solution text | 593 / 623 | 95.2% |
| CVSS v2 base score | 294 / 623 | 47.2% |
| CVE reference | 265 / 623 | 42.5% |
| VPR score | 265 / 623 | 42.5% |
| EPSS score (scanner cached) | 265 / 623 | 42.5% |
| Patch publication date | 248 / 623 | 39.8% |
| Exploit available flag | 224 / 623 | 36.0% |
| CVSS v3 base score | 51 / 623 | 8.2% |
| Exploit code maturity | 0 / 623 | 0% |

Four observations follow.

**Fewer than half of all findings have a CVE.** This is not a data quality problem. Service
detections, configuration weaknesses and informational findings have no CVE by nature. The
weak VNC password identified in Stage 1 is one of them: Critical severity, demonstrated by the
scanner logging in successfully, and carrying no CVE, no CVSS and no EPSS. Any pipeline keyed
on CVE discards it.

**CVSS v3 covers 8.2% of findings.** Older plugins carry v2 only. A model built on v3 would
ignore 92% of the dataset, and a model that silently falls back from v3 to v2 is comparing
scores from two different scales.

**EPSS coverage exactly matches CVE coverage.** Expected, since EPSS is keyed on CVE, but it
confirms the ceiling: no enrichment source keyed on CVE can ever cover more than 42.5% of these
findings.

**The best-covered field is the one describing what to do.** Remediation guidance is present on
95.2% of findings, better than any scoring field. Most vulnerability reporting leads with
severity distributions; the actionable content is more complete than the scores used to rank it.

---

## Enrichment

Two public sources, both free and unauthenticated.

**FIRST EPSS** gives the probability that a CVE will be exploited in the next 30 days. It is a
prediction: continuous, updated daily, and covering published CVEs that have been through its
model.

**CISA KEV** is a catalogue of vulnerabilities confirmed as exploited in the wild. It is an
observation: binary and authoritative. A high EPSS score means likely. KEV membership means it
has already happened.

808 distinct CVEs were queried in batches of 80, within the API's 2000-character parameter
limit. All 808 returned scores. The KEV catalogue returned 1,726 entries.

### Design decisions

**Worst case governs a multi-CVE finding.** A single finding can reference many CVEs: the curl
advisory from Stage 2 references ten. The enrichment takes the highest EPSS among them and marks
KEV membership if any one of them is listed. A finding is as dangerous as its most exploitable
component.

**Missing stays missing.** A finding with no EPSS score is recorded as null, never as zero. The
two are different claims: "not scored" and "scored as negligible" must not collapse into the
same value, because the second would push unscorable findings to the bottom of any ranking.

**Live values recorded separately from cached ones.** The scanner carries its own EPSS values.
These were stored alongside the live ones rather than overwriting them, to measure drift between
a cached plugin feed and the current source.

Drift turned out to be zero: every cached value matched the live query. Worth stating plainly
rather than implying a gap that did not exist. The benefit of querying the source directly here
is current data as a guarantee rather than as a coincidence.

---

## What the enriched data shows

### Confirmed active exploitation

Four distinct findings appear on the CISA KEV catalogue:

| Severity | EPSS | Finding |
|---|---|---|
| Critical | 1.0000 | Bash Remote Code Execution (Shellshock) |
| High | 1.0000 | Ubuntu kernel vulnerabilities |
| Critical | 0.9927 | Apache Tomcat AJP Connector Request Injection (Ghostcat) |
| Critical | 0.1447 | Ubuntu package vulnerabilities |

Of 37 Critical findings, three are known to be actively exploited.

### Severity and exploitation likelihood disagree

Eleven findings rated Medium or Low carry an EPSS score above 0.80:

| Severity | EPSS | Finding |
|---|---|---|
| Low | 1.0000 | SSLv3 Padding Oracle (POODLE) |
| Low | 0.9986 | SSL/TLS EXPORT_DHE 512-bit export ciphers |
| Medium | 0.9869 | SSL/TLS EXPORT_RSA 512-bit cipher suites |
| Medium | 0.9650 | Ubuntu package vulnerabilities |
| Medium | 0.9342 | ISC BIND denial of service |
| Medium | 0.8442 | SSL RC4 cipher suites (Bar Mitzvah) |
| Medium | 0.8211 | SSL DROWN attack |

**POODLE is rated Low and carries the maximum EPSS score.**

Meanwhile, of the 25 Critical findings that could be scored, ten sit below 0.15, and the lowest
is 0.0186.

Ranked strictly by severity, an engineer works through 37 Critical findings before reaching a
Low-severity vulnerability that the model rates as certain to be exploited. Several of those
Criticals are an order of magnitude less likely to be exploited than the Low they are ranked
above.

This is the argument the project exists to make, now supported by measured data from the
environment rather than asserted.

### Twelve Criticals cannot be enriched at all

Of 37 Critical findings, 12 have no CVE and therefore no EPSS and no KEV status. They include
the weak VNC password, which the scanner confirmed by authenticating to the service.

A finding the scanner proved exploitable has less enrichment data available than one it inferred
from a version string. Any model weighting EPSS heavily will rank demonstrated findings below
predicted ones unless this is handled deliberately.

---

## Constraints for the scoring engine

Stage 3 produced five requirements that Stage 4 has to satisfy.

1. **No single signal covers the dataset.** The most-covered scoring field reaches 47%. The
   model must degrade through tiers rather than depend on any one input.

2. **Absent is not zero.** A finding without EPSS must not rank below one with a measured EPSS
   of 0.001.

3. **CVSS versions cannot be mixed naively.** v2 and v3 use different scales and different
   vectors. Falling back from one to the other needs an explicit rule.

4. **Non-CVE findings must remain rankable.** Configuration weaknesses and confirmed credential
   failures carry real risk and no enrichment data.

5. **Confirmed should outrank inferred.** KEV membership and scanner-demonstrated exploitation
   are evidence. CVSS and EPSS are estimates. The model should distinguish them.

---

## Code

| File | Purpose |
|---|---|
| `src/parse_nessus.py` | Normalises raw scan exports into a single finding schema |
| `src/enrich.py` | Queries FIRST EPSS and CISA KEV, attaches results |
| `data/findings.json` | 623 normalised findings |
| `data/enriched.json` | The same, with live exploit intelligence |

Both scripts use only the Python standard library. The pipeline runs entirely offline against
captured data and does not require an active scanner licence.

---

## Screenshots

| File | Content |
|---|---|
| `01-enrichment-report.png` | Enrichment run: 808 CVEs scored, KEV matches, and the findings where severity and exploitation likelihood diverge |

---

## Stage 3 outcome

- 623 findings extracted from five scan runs and normalised into a consistent schema
- Three silent data failures identified and corrected, each of which would have produced
  confident and wrong analysis
- Signal coverage measured across the dataset, establishing what a scoring model can be built on
- 808 CVEs enriched against live EPSS and the CISA KEV catalogue
- The project's central claim evidenced from measured data: severity ranking misorders the
  remediation queue

**Next:** a scoring model that combines these signals, degrades sensibly where they are absent,
and produces a ranking that can be compared directly against severity ordering.
