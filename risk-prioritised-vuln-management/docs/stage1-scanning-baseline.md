# Stage 1: Scanning Baseline and Coverage Analysis

## Objective

Establish a controlled lab environment, run authenticated and unauthenticated vulnerability
assessments against a known-vulnerable host, and quantify the difference in visibility between
the two methods.

The wider project builds a risk-based prioritisation pipeline on top of this data. Stage 1
produces the raw findings and establishes two things the later stages depend on: that severity
ratings alone are a poor guide to action, and that scan configuration determines how much of the
estate you can actually see.

---

## Environment

| Component | Detail |
|---|---|
| Hypervisor | VMware Workstation |
| Scanner host | Kali Linux, `192.168.32.132` |
| Target | Metasploitable 2 (Ubuntu 8.04 LTS), `192.168.32.128` |
| Scanner | Tenable Nessus Essentials 10.12.4 |
| Network | Isolated VMware segment, `192.168.32.0/24` |
| Severity base | CVSS v3.0 |

Metasploitable 2 is a deliberately vulnerable virtual machine published by Rapid7 for
assessment practice. It is never exposed to an untrusted network.

### A note on network design

The lab was initially built with the scanner on a bridged adapter, which placed it on the host's
physical LAN. This was corrected to a dedicated VMware segment so that scanning traffic and the
vulnerable target remain contained.

The diagnostic worth recording: the scanner had an active link and an IPv6 address but no IPv4
lease. `nmcli device status` reported the interface as connected, which ruled out anything inside
the guest and pointed at the virtual network itself. The adapter was attached to a segment with
no IPv4 DHCP service running.

---

## Assessment 1: Unauthenticated baseline

Basic Network Scan, no credentials supplied. This represents what an external attacker or an
unauthenticated internal scanner can determine about the host.

**Duration:** 36 minutes · **Authentication:** Failed (expected) · **Unique plugins:** 65

| Severity | Count |
|---|---|
| Critical | 9 |
| High | 5 |
| Medium | 22 |
| Low | 8 |
| Informational | 130 |
| **Total** | **174** |

33 distinct CVEs identified. Two remediation actions proposed.

### Selected findings

| Finding | Severity | CVSS | EPSS |
|---|---|---|---|
| Canonical Ubuntu Linux SEoL (8.04.x) | Critical | 10.0 | n/a |
| VNC Server 'password' Password | Critical | 10.0 (v2) | n/a |
| Apache Tomcat AJP Connector Request Injection (Ghostcat) | Critical | 9.8 | 0.9927 |
| SSL Version 2 and 3 Protocol Detection | Critical | 9.8 | n/a |
| Bind Shell Backdoor Detection | Critical | 9.8 | n/a |
| Samba Badlock Vulnerability | High | 7.5 | 0.3693 |
| NFS Shares World Readable | High | 7.5 | n/a |
| SSL DROWN Attack | Medium | 5.9 | 0.8211 |

---

## Assessment 2: Authenticated scan

Identical scope and template, with SSH password credentials supplied. Authentication succeeded,
confirmed by the scanner's own `Auth: Pass` status, a check worth making every time, because a
failed credential set produces a scan that looks complete and silently is not.

**Duration:** 70 minutes · **Authentication:** Passed · **Unique plugins:** 87

| Severity | Unauthenticated | Authenticated | Change |
|---|---|---|---|
| Critical | 9 | 27 | +200% |
| High | 5 | 93 | +1,760% |
| Medium | 22 | 137 | +523% |
| Low | 8 | 17 | +113% |
| Informational | 130 | 182 | +40% |
| **Total** | **174** | **456** | **+162%** |

Remediation actions rose from 2 to 68.

### What this means

**95% of the High-severity findings on this host were invisible to unauthenticated scanning.**
Five were visible externally; ninety-three existed. A programme relying on unauthenticated scans
would have assessed this host, produced a report, and missed the overwhelming majority of its
high-severity exposure.

The mechanism is straightforward. Without credentials the scanner infers software versions from
network banners and service responses. With credentials it reads the installed package
manifest directly. Anything not exposed to the network, such as local privilege escalation, vulnerable
libraries behind a service or missing patches on non-listening software, is simply unreachable
from outside.

The jump in remediation guidance from 2 to 68 matters as much as the finding count.
Unauthenticated scanning tells you something may be wrong. Authenticated scanning tells you
which package to update.

---

## Finding detail: Bash Remote Code Execution (Shellshock)

Plugin 77823 · Critical · CVSS v3.0 9.8 · VPR 9.6 · EPSS 1.0

Selected because it demonstrates several things at once.

**It was confirmed, not inferred.** The scanner injected a crafted environment variable through
an SSH connection and executed `/usr/bin/id` on the host, reading back the resulting user and
group membership. It then removed its own temporary file. This is proof of remote code
execution, not a version-string guess.

**It was only visible with credentials.** The plugin type is `local` and the check ran through
the authenticated session. The unauthenticated baseline did not report it.

**Every scoring signal agrees.** CVSS 9.8, VPR 9.6, EPSS 1.0. Tenable's VPR key drivers list
Exploit Code Maturity as High and vulnerability age at 730 days or more. Where all signals
converge, prioritisation is uncontroversial, which makes the cases where they diverge the
interesting ones.

---

## The prioritisation problem

The baseline scan contains a clear illustration of why severity ranking alone is insufficient.

| Finding | Severity | CVSS | EPSS |
|---|---|---|---|
| Apache Tomcat AJP (Ghostcat) | Critical | 9.8 | 0.9927 |
| **SSL DROWN Attack** | **Medium** | **5.9** | **0.8211** |
| Samba Badlock | High | 7.5 | 0.3693 |

SSL DROWN is rated Medium. Its exploit probability is higher than every Critical finding on the
host except one. Samba Badlock is rated High and carries less than half DROWN's exploitation
likelihood.

Triaging strictly by severity, an engineer would work through nine Critical findings before
reaching a Medium that is more likely to be exploited than most of them.

This is the problem the remainder of the project addresses: combining CVSS, EPSS, CISA KEV
membership, and asset context into a single prioritisation that reflects likelihood of
exploitation rather than theoretical impact alone.

### Findings are not uniformly scored

A practical constraint discovered while reviewing the data, and one that any scoring
implementation has to handle:

- Some plugins carry only CVSS v2 scores (VNC Server 'password' Password, published 2012)
- Some carry CVSS v3
- The scanner supports v2, v3 and v4 as severity bases
- EPSS is present on some findings and absent on others
- VPR is present on some findings and absent on others

A scoring engine cannot assume a complete, consistent set of inputs. It needs defined fallback
behaviour for each missing signal.

### Not every finding is a patch

Three findings from this host require three different responses:

- **Shellshock**: apply a package update
- **VNC weak password**: a configuration change, no patch exists
- **Bind Shell Backdoor Detection**: on a production host this indicates an existing
  compromise and belongs to incident response, not vulnerability management

A ticketing integration that treats all findings as patch work will route a significant
proportion of them to the wrong team.

### Root cause versus symptom

The host runs Ubuntu 8.04, flagged as `Canonical Ubuntu Linux SEoL` at CVSS 10.0. The operating
system is end-of-life and receives no security updates.

Most of the 456 findings are downstream of that single fact. Remediating them individually is
not possible; the correct action is to rebuild the host on a supported platform. Stakeholder
reporting that presents 456 discrete items obscures the one decision that actually matters.

---

## Scanner API assessment

Stage 3 of this project requires programmatic extraction of scan results. The Nessus REST API
was assessed to determine what the Essentials licence permits.

**Authentication:** API keys generated via Settings → My Account → API Keys. Keys passed in the
`X-ApiKeys` header. Authentication succeeded.

**Bulk export, blocked:**

```
POST /scans/{id}/export  {"format":"csv"}
→ {"error":"csv reports are not available for Essentials Free"}

POST /scans/{id}/export  {"format":"nessus"}
→ {"error":"nessus exports are not available for Essentials Free"}
```

**Read endpoints, available:**

```
GET /scans          → scan list with IDs, status, timestamps
GET /scans/{id}     → full vulnerabilities array
```

The scan detail endpoint returns per-finding objects containing `plugin_id`, `plugin_name`,
`severity`, `plugin_family`, `count`, and the remediation set. This is sufficient input for the
prioritisation pipeline without using the export endpoint at all.

Notably, the response includes `vpr_score` and `epss_score` fields, both returned as `null` under
this licence tier. Populating equivalent values from public sources, the FIRST EPSS API and the
CISA KEV catalogue, is precisely what Stage 4 implements.

**Architecture decision:** the pipeline reads from `/scans/{id}` and iterates the vulnerability
array, rather than requesting a bulk export. An alternative scanner with unrestricted export was
evaluated and rejected as unnecessary once read access was confirmed.

---

## Credential handling

API keys are held in environment variables and never committed. The repository contains
`.env.example` listing required variable names with placeholder values.

Worth stating explicitly, because it is a real consideration rather than a formality:
authenticated scanning requires the scanner to hold login credentials for every host in scope.
In a production environment this is a dedicated service account using key-based authentication,
with scope limited to the assets it needs. The scanner itself becomes part of the attack surface
it is assessing.

---

## Screenshots

| File | Content |
|---|---|
| `01-baseline-scan-summary.png` | Unauthenticated scan results and severity distribution |
| `02-baseline-vulnerabilities.png` | Findings list showing CVSS, VPR and EPSS columns |
| `03-critical-finding-detail.png` | Shellshock detail with confirmed exploitation output |
| `04-credentialed-scan-summary.png` | Authenticated results, `Auth: Pass` |
| `05-scan-comparison.png` | Both assessments in the scan list |

---

## Stage 1 outcome

- Isolated lab environment built and network-verified
- Two assessments completed against a common target with a controlled variable
- Coverage gap quantified: 95% of High-severity findings require authentication to detect
- Prioritisation problem evidenced from live data rather than asserted
- Scanner API capability mapped and pipeline architecture decided

**Next:** cloud target environment, then programmatic extraction of these findings via the REST
API for enrichment and scoring.
