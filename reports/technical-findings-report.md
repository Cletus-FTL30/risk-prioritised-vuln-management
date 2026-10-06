# Vulnerability Assessment: Technical Findings Report

---

## Scope and method

Authenticated and unauthenticated network scanning, with findings enriched against two external sources and ranked by a risk model combining severity, exploitation likelihood and asset context.

| | |
|---|---|
| Systems assessed | 2 |
| Raw findings | 623 |
| Actionable findings | 325 |
| Distinct vulnerability-host pairs | 292 |
| Carrying a CVE identifier | 245 (84%) |
| Scored for exploitation likelihood | 245 (84%) |

Enrichment sources: FIRST EPSS (exploitation probability) and the CISA Known Exploited Vulnerabilities catalogue (confirmed exploitation).

## Summary of findings

| Severity | Count |
|---|---|
| Critical | 31 |
| High | 108 |
| Medium | 136 |
| Low | 17 |
| **Total** | **292** |

Severity is the scanner's own rating and is reported here for reference. Remediation order in this report is set by risk score, which accounts for exploitation likelihood and asset exposure as well as severity.

## By system

| System | Findings | Critical + High | Actively exploited | Urgent |
|---|---|---|---|---|
| metasploitable (`192.168.32.128`) | 265 | 118 | 4 | 17 |
| vuln-lab-ubuntu (`13.41.110.165`) | 27 | 21 | 0 | 0 |

**vuln-lab-ubuntu** carries 21 findings rated Critical or High but none requiring urgent action. Its findings are recent vendor patches for which no exploitation has been observed or predicted. This is the case the risk model exists to distinguish: a high severity count is not the same as a high risk.

## Confirmed active exploitation

Listed in the CISA Known Exploited Vulnerabilities catalogue. These are not predictions. Exploitation has been observed in the wild.

| Risk | EPSS | System | Finding |
|---|---|---|---|
| 80 | 1.00 | metasploitable | Bash Remote Code Execution (Shellshock) |
| 80 | 1.00 | metasploitable | Ubuntu 8.04 LTS / 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : ph |
| 80 | 0.99 | metasploitable | Apache Tomcat AJP Connector Request Injection (Ghostcat) |
| 80 | 0.14 | metasploitable | Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS / 10.10 |

All are assigned the shortest remediation deadline regardless of their individual severity rating, because observed exploitation outranks predicted exploitation.

## Priority remediation queue

The 17 findings requiring action within 14 days, in order.

| # | Risk | Deadline | Severity | EPSS | System | Finding |
|---|---|---|---|---|---|---|
| 1 | 80 | 7 days | High | 1.00 | metasploitable | Ubuntu 8.04 LTS / 10.04 LTS / 11.04 / 11.10 / 12.0 |
| 2 | 80 | 7 days | Critical | 0.14 | metasploitable | Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 L |
| 3 | 80 | 7 days | Critical | 1.00 | metasploitable | Bash Remote Code Execution (Shellshock) |
| 4 | 80 | 7 days | Critical | 0.99 | metasploitable | Apache Tomcat AJP Connector Request Injection (Gho |
| 5 | 69 | 14 days | High | 0.99 | metasploitable | Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 : apac |
| 6 | 66 | 14 days | High | 0.95 | metasploitable | SSL Medium Strength Cipher Suites Supported (SWEET |
| 7 | 65 | 14 days | Critical | 0.74 | metasploitable | Ubuntu 8.04 LTS / 10.04 LTS / 11.04 / 11.10 : samb |
| 8 | 63 | 14 days | Critical | 0.71 | metasploitable | Debian OpenSSH/OpenSSL Package Random Number Gener |
| 9 | 63 | 14 days | Critical | 0.71 | metasploitable | Debian OpenSSH/OpenSSL Package Random Number Gener |
| 10 | 63 | 14 days | High | 0.87 | metasploitable | Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 / 9.10 :  |
| 11 | 62 | 14 days | Critical | 0.71 | metasploitable | Weak Debian OpenSSH Keys in ~/.ssh/authorized_keys |
| 12 | 62 | 14 days | High | 0.84 | metasploitable | Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10 |
| 13 | 61 | 14 days | High | 0.83 | metasploitable | Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.1 |
| 14 | 61 | 14 days | High | 0.83 | metasploitable | Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.1 |
| 15 | 61 | 14 days | Medium | 0.93 | metasploitable | ISC BIND Denial of Service |
| 16 | 60 | 14 days | High | 0.69 | metasploitable | Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : samba v |
| 17 | 60 | 14 days | High | 0.69 | metasploitable | Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : samba r |

## Where severity ranking would misdirect effort

**86 findings rated Critical or High score below 40 on the risk model.** They have low measured exploitation likelihood and sit on systems with limited exposure. Remediating them ahead of the priority queue would consume effort for little risk reduction.

**1 finding rated Medium or Low score 60 or above.** Ranked by severity alone it would sit far down the queue despite high exploitation likelihood.

| Severity | EPSS | Risk | Finding |
|---|---|---|---|
| Medium | 0.93 | 61 | ISC BIND Denial of Service |

## Exposure duration

Time elapsed since the vendor published a fix, for the 239 findings where a patch date is recorded.

| | |
|---|---|
| Median | 15.7 years |
| Oldest | 18.4 years |
| Fix available over 10 years | 235 findings |

Patch age measures how long a known weakness has gone unaddressed, which is a better indicator of remediation performance than a count of open findings. A programme closing findings faster than new ones appear will still show a rising median if the oldest are never touched.

## Remediation schedule

| Priority | Deadline | Findings |
|---|---|---|
| Critical | 7 days | 4 |
| High | 14 days | 13 |
| Moderate | 30 days | 49 |
| Low | 90 days | 169 |
| Planning | 180 days | 57 |
| **Total** | | **292** |

## Scoring methodology

```
risk = (0.4 x impact + 0.6 x likelihood) x asset_multiplier
```

Likelihood carries the greater weight. Each input degrades explicitly where data is absent rather than defaulting to zero, because a finding with no exploitation data is not the same as one measured as unlikely.

| Input | Source, strongest first |
|---|---|
| Likelihood | CISA KEV, FIRST EPSS, exploit availability, neutral |
| Impact | CVSS v3, CVSS v2, scanner severity rating |
| Asset | Business criticality and network exposure |

Findings confirmed as actively exploited are assigned a minimum score so that observation cannot be outranked by estimation.

---

*Generated from scored assessment data. Figures regenerate with each scan cycle.*
