# Risk-Prioritised Vulnerability Management

A working pipeline that scans hosts, extracts findings programmatically, enriches them with live
exploit intelligence, and ranks them by risk rather than by severity label.

Built with Tenable Nessus, Python, AWS, FIRST EPSS and the CISA Known Exploited Vulnerabilities
catalogue.

---

## The problem

Severity ratings describe how bad a vulnerability would be. They say nothing about whether
anyone is exploiting it.

From the assessments in this project:

| Finding | Severity | EPSS |
|---|---|---|
| SSLv3 Padding Oracle (POODLE) | **Low** | **1.0000** |
| SSL/TLS EXPORT_DHE 512-bit ciphers | Low | 0.9986 |
| ISC BIND denial of service | Medium | 0.9342 |
| Ubuntu kernel vulnerabilities | Critical | 0.0568 |
| Ubuntu apt vulnerabilities | Critical | 0.0186 |

POODLE is rated Low and carries the maximum exploitation probability the model can assign. Two
Critical findings are two orders of magnitude less likely to be exploited.

Ranked by severity, an engineer clears 280 findings before reaching POODLE.

---

## Results

**623 findings** across five scan runs and two hosts, enriched against **808 CVEs** and ranked
by a scoring model combining impact, exploitation likelihood and asset context.

| | |
|---|---|
| High-severity findings invisible to unauthenticated scanning | **95%** |
| Critical and High findings on a newly launched, patched cloud host | **21** |
| Distinct vulnerabilities ranked and ticketed | **292** |
| POODLE: severity rank to risk rank | **281 to 38** |
| Critical finding at EPSS 0.0568: severity rank to risk rank | **2 to 94** |
| **Findings needing attention within a fortnight** | **17 of 292** |
| Critical/High findings scoring below 40 on the risk model | **86** |
| Median time since a vendor fix was published | **15.7 years** |

---

## Architecture

```
Nessus scans --> REST API --> Enrichment --> Scoring --> Routing --> ServiceNow
     |                            |             |           |            |
     |                     FIRST EPSS    Asset context   Team +      CMDB-linked
     |                     CISA KEV      Exposure        SLA from    remediation
     |                                   Criticality     risk score  records
     +-- Lab target (VMware)
     +-- Cloud target (AWS EC2)
```

**Scoring model**

```
risk = (0.4 x impact + 0.6 x likelihood) x asset_multiplier
```

Likelihood carries the larger weight by design. Each input degrades explicitly where data is
absent, because no single signal covers more than 47% of the dataset.

| Input | Source | Tiers |
|---|---|---|
| Likelihood | CISA KEV, FIRST EPSS, exploit flags | 4, strongest first |
| Impact | CVSS v3, CVSS v2, severity rating | 3, with source recorded |
| Asset | Inventory: criticality and exposure | Applied separately |

Confirmed exploitation sets a score floor. Observation overrides prediction.

**Remediation deadlines** come from risk score, not severity. Because the KEV floor is 80 and
the top SLA band starts at 80, every confirmed-exploited finding lands on a 7-day deadline
automatically, whatever its CVSS score.

| Risk score | Deadline | Findings |
|---|---|---|
| 80+ | 7 days | 4 |
| 60-79 | 14 days | 13 |
| 40-59 | 30 days | 49 |
| 20-39 | 90 days | 169 |
| under 20 | 180 days | 57 |

---

## Stages

**1. Scanning baseline and coverage analysis** — complete

Isolated lab on VMware, authenticated and unauthenticated assessments of a common target.

Result: **95% of High-severity findings were invisible to unauthenticated scanning**, five
detected externally against ninety-three present.

[Write-up](docs/stage1-scanning-baseline.md)

**2. Cloud host assessment and remediation cycle** — complete

AWS environment with account controls applied before any workload. Full cycle: scan, verify
against the host, remediate, rescan, confirm.

Result: a newly launched, fully patched Ubuntu instance from the official image presented
**zero findings externally and 21 Critical and High when scanned with credentials**, including
a remote code execution fix published three months before the instance launched.

[Write-up](docs/stage2-cloud-assessment.md)

**3. Extraction, normalisation and enrichment** — complete

Programmatic extraction via the REST API, normalisation into a single schema, enrichment
against FIRST EPSS and the CISA KEV catalogue.

Result: 623 findings, 808 CVEs enriched, and a measured account of signal coverage. Three
silent data failures identified and corrected, each of which would have produced confident and
wrong analysis.

[Write-up](docs/stage3-extraction-enrichment.md)

**4. Risk scoring model** — complete

A tiered model combining impact, likelihood and asset context, with every score fully
auditable.

Result: the ranking reorders substantially against severity. Asset weighting was found to
dominate the first configuration, measured, and corrected. One design constraint remains
unsatisfied and is documented rather than hidden.

[Write-up](docs/stage4-risk-scoring.md)

**5. CMDB integration and remediation records** — complete

A custom vulnerable item schema built in ServiceNow, with findings joined to configuration
items, routed to owning teams, and carrying deadlines derived from risk score.

Result: **292 findings become 17 requiring attention within a fortnight**. Routing was found to
misclassify package updates as configuration work, and corrected to check whether a vendor fix
exists before matching on keywords.

[Write-up](docs/stage5-cmdb-ticketing.md)

**6. Reporting** — complete

An executive summary and a technical findings report, both generated from the scored dataset so
they cannot disagree with each other or go stale separately.

Result: **91% of findings traced to one unsupported system**, resolvable by a single decision
rather than 265 patches. Median time since a vendor fix was published: **15.7 years**.

[Write-up](docs/stage6-reporting.md) · [Executive summary](reports/executive-summary.md) ·
[Technical report](reports/technical-findings-report.md)

---

## Design decisions

**Reading rather than exporting.** The scanner's bulk export is licence restricted. The pipeline
reads the scan detail endpoint and iterates the vulnerability array instead. An alternative
scanner was evaluated and rejected as unnecessary once read access was confirmed.

**Missing is not zero.** Over half the findings carry no CVE, so no CVE-keyed source can score
them. A finding with no EPSS data is recorded as null and assigned a neutral likelihood, never
zero. Otherwise a weak credential the scanner proved by logging in would rank below a
vulnerability nobody has ever exploited.

**Confirmed outranks predicted.** EPSS estimates. CISA KEV observes. Where they disagree, the
observation wins.

**Not everything is a patch.** Findings split into package updates, configuration changes, and
indicators of existing compromise. These need different teams and different workflows.

**Root cause over symptom count.** The lab target runs an end-of-life operating system. Most of
its findings are downstream of that single fact. Reporting 456 discrete items obscures the one
decision that matters.

---

## What did not work first time

Documented in full in the stage write-ups, because the diagnosis is the useful part:

- An authenticated scan reported success while silently failing its package checks. The initial
  hypothesis, that the target was defending itself, was disproved by the target's own logs. The
  cause was in the network path.
- The scanner API returned a cancelled scan run as current, and the wrong run for another host.
  Neither produced an error.
- A boolean field arriving as the string `"false"` marked every scan as authenticated,
  including both unauthenticated baselines. This would have made the project's central finding
  unprovable from its own data.
- The scoring model's first configuration let asset weighting overwhelm exploit evidence,
  ranking findings with no EPSS data above the highest-scoring vulnerability in the dataset.
- Ticket routing matched keywords in finding names, which sent `openssl vulnerabilities
  (USN-8414-1)` to the configuration team because of three letters in its title, and sent a
  genuine weak-key finding to the patching team. Checking for a published vendor fix before
  matching keywords corrected both.

---

## Repository

```
docs/           stage write-ups and analysis
src/            pipeline source
data/           normalised, enriched, scored and ticketed datasets
reports/        generated executive and technical reports
screenshots/    assessment evidence
assets.json     asset inventory and scoring weights
```

| Script | Does |
|---|---|
| `parse_nessus.py` | Normalises raw scan exports into one finding schema |
| `enrich.py` | Queries FIRST EPSS and the CISA KEV catalogue |
| `score.py` | Ranks by risk, with every score fully auditable |
| `push_servicenow.py` | Routes to teams, sets deadlines, creates records |
| `report.py` | Generates the executive and technical reports |

All scripts use the Python standard library only. The pipeline runs offline against captured
data and requires no active scanner licence.

Credentials are held in environment variables and never committed.

---

## Status

All six stages complete. Findings, figures and screenshots throughout are from assessments run
in this environment, not illustrative examples.
