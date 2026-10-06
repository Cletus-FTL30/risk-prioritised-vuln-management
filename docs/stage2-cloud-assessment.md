# Stage 2: Cloud Host Assessment and Remediation Cycle

## Objective

Extend the assessment from a deliberately vulnerable lab host to a real cloud instance, and
complete a full vulnerability management cycle: scan, verify, remediate, rescan, confirm.

Stage 1 established that authenticated scanning sees substantially more than unauthenticated
scanning, using a host built to be vulnerable. Stage 2 tests whether that finding holds on a
current, patched, correctly configured cloud server, which is a far less forgiving test.

---

## Environment

| Component | Detail |
|---|---|
| Provider | AWS, Europe (London) eu-west-2 |
| Instance | t3.micro, Ubuntu Server 26.04 LTS |
| Image | Official Canonical AMI |
| Storage | 8 GiB gp3 |
| Access | SSH key pair, no password authentication |
| Scanner | Nessus Essentials on Kali Linux, scanning over the internet |

### Account controls applied before any workload

- MFA enabled on the root account
- A separate IAM user created for daily work, placed in a group with permissions attached to
  the group rather than the user
- MFA enabled on that user
- Root reserved for billing and account recovery only
- A monthly cost budget set at a deliberately low threshold, alerting on both actual and
  forecast spend

The permissions model is not least privilege. A single administrative group is appropriate for
a one-person lab, but a production account would scope permissions by function and use identity
federation rather than long-lived IAM users. The choice here is convenience, and it is worth
naming as such.

### The launch wizard's default is the misconfiguration

The EC2 launch wizard proposes an SSH rule with a source of `0.0.0.0/0`, which exposes the
management port to the entire internet. This was changed to a single-address source before
launch.

This is worth recording because "SSH open to the world" is one of the most frequently reported
findings in cloud security assessments, and the reason is visible here: it is what the console
suggests by default, and accepting defaults is the path of least resistance.

The instance also launched with IMDSv2 required, which is now the default. That control exists
because of the metadata service abuse seen in the 2019 Capital One breach. Secure by default in
one place, insecure by default in another, in the same wizard.

---

## Network verification

Before scanning, two checks established what the security group was actually doing:

```
ping    → 100% packet loss
nc -zv  → port 22 open
```

Both results are correct. The security group permits TCP 22 from one address and silently drops
everything else, including ICMP. A failed ping does not mean a host is down, and a scanner
configured to skip hosts that do not respond to ping would have reported this instance as
unreachable.

---

## Assessment 1: unauthenticated

External scan, no credentials. 24 minutes.

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 12 |

Nothing actionable. From outside, with one port open and a current operating system, the host
presents no attack surface worth reporting.

---

## Troubleshooting: the scan that looked like it worked

The first authenticated attempt completed in three minutes and reported `Auth: Fail` with 17
informational findings.

Three findings together explained the state:

- `Target Credential Status - Valid Credentials Provided` — authentication succeeded
- `Target Credential Issues - Intermittent Authentication Failure` — but not consistently
- `OS Security Patch Assessment Failed` — so the package checks never ran

The plugin output named the specific failure:

```
open_connection() failed on previously successful connection:
Failed to open a socket on port 22
```

### Ruling out the target

The initial hypothesis was that OpenSSH was defending itself. Recent OpenSSH versions include
per-source penalties that temporarily refuse connections from an address behaving like a
scanner, and the host runs OpenSSH 10.2.

The server logs did not support this:

```
journalctl -u ssh -u ssh.socket
```

No penalties, no refusals, no service restarts. Every connection that reached the instance was
handled normally. The failed connections never arrived.

The logs did show what a scanner looks like from the defending side: repeated
`banner exchange: invalid format` entries as the scanner sent non-SSH data to fingerprint the
service.

### Locating the actual cause

If the target never refused the connections, something in the path did. The scanner runs in a
virtual machine behind NAT on a workstation running endpoint security software, and connects to
AWS over a residential link. Any of those can drop connections when a scanner opens many in
quick succession. The Stage 1 target was on the same local network as the scanner and never
traversed that path, which is why the problem appeared only now.

### Resolution

Rather than weakening a control on the target or the workstation, the scan itself was throttled
using the scanner's low-bandwidth profile. The next run authenticated successfully and completed
in 16 minutes.

Tuning a scan to its network path is ordinary practice when scanning through firewalls, proxies
or NAT. The general lesson is narrower and more useful: the first explanation was wrong, and the
evidence that disproved it came from the target's own logs rather than from the scanner.

---

## Assessment 2: authenticated

Same host, same hour, credentials supplied. 16 minutes.

| Severity | Unauthenticated | Authenticated |
|---|---|---|
| Critical | 0 | 5 |
| High | 0 | 16 |
| Medium | 0 | 5 |
| Informational | 12 | 55 |

**21 Critical and High findings on a host that presented zero from outside.**

### The Critical findings

| Package | Advisory | CVSS |
|---|---|---|
| curl | USN-8487-1 | 9.8 |
| OpenSSH | USN-8533-1 | 9.4 |
| Wget | USN-8543-1 | 9.1 |
| OpenSSL | USN-8414-1 | 9.1 |
| Ubuntu Advantage Tools | USN-8555-1 | 9.0 |

The sixteen High findings covered the Linux kernel, Vim, SQLite, libssh2, Gzip, Python,
httplib2, NTFS-3G and Inetutils.

Every finding references an Ubuntu Security Notice, meaning a fix was already published for all
of them. These are not unknown vulnerabilities. They are known vulnerabilities on a host that
had not yet applied the fixes.

### A newly launched instance is not a current instance

The curl advisory was published on 25 June 2026, with the fix released on 30 June. The instance
was launched in late September, from the current official image, and still carried the
vulnerable version.

Cloud images are not rebuilt for every security update. An instance is current as of its image's
build date, not its launch date, and the gap between those two is exposure that exists from the
first second the instance runs.

---

## How the scanner reaches its conclusions

The curl finding states its own method plainly:

> Nessus has not tested for these issues but has instead relied only on the application's
> self-reported version number.

Output:

```
Installed package : curl_8.18.0-1ubuntu2.1
Fixed package     : curl_8.18.0-1ubuntu2.2
```

This is inference from a version string. Compare it with the Shellshock finding from Stage 1,
where the scanner injected a payload, executed a command on the host and read the result back.
Both are reported as Critical. Only one was demonstrated.

That distinction belongs in a risk model. A confirmed finding and an inferred finding carry
different confidence, and a prioritisation system that treats them identically is discarding
information the scanner has already provided.

### One finding is not one vulnerability

The single curl entry references ten CVEs, including a use-after-free permitting possible code
execution and a TLS verification bypass. Counting findings and counting vulnerabilities produce
different numbers, which matters for both metrics and ticketing.

---

## Verification against the host

Scanner output is a claim until it is checked. Querying the host directly:

```
apt list --upgradable   → 49 packages pending
dpkg -l | grep curl     → curl 8.18.0-1ubuntu2.5
```

The installed version was ahead of the version the scan reported, and ahead of the version the
advisory required.

The most likely explanation is unattended upgrades, which are enabled by default on Ubuntu cloud
images and apply security updates automatically. The host patched itself between the scan and
the verification.

Two observations follow.

**A scan result begins ageing the moment it completes.** The findings were accurate when
recorded and inaccurate an hour later. Any pipeline that raises tickets automatically will raise
some for vulnerabilities that no longer exist, unless it re-verifies before ticketing.

**Not every pending update is a security update.** The package list distinguishes
`-security` from `-updates`. Of 49 pending packages, only a subset carried security advisories.
The scanner is already performing a filtering step that a naive "count of outdated packages"
metric would miss.

---

## Remediation cycle

| Stage | Critical | High | Medium | Low |
|---|---|---|---|---|
| Unauthenticated baseline | 0 | 0 | 0 | 0 |
| Authenticated | 5 | 16 | 5 | 0 |
| After patching | 0 | 1 | 0 | 0 |
| After reboot | 0 | 0 | 0 | 0 |

Patching cleared twenty of the twenty-one findings. The survivor was the Linux kernel
(USN-8488-1), which requires a reboot to take effect. A rescan after reboot returned no findings
above informational.

The kernel finding is the interesting one operationally. Patching alone did not resolve it, and
in a production environment the reboot would require a change window, downtime approval and
potentially a maintenance schedule weeks out. The technical fix takes seconds; the organisational
fix does not. A remediation SLA that ignores this distinction will be missed routinely.

### Signals disagreed on the kernel finding

| Signal | Value |
|---|---|
| CVSS v3 | 7.8 |
| VPR | 9.4 |
| EPSS | 0.0016 |

Near the top of one priority scale, near the bottom of another. Any scoring model has to decide
what to do when its inputs point in opposite directions, and that decision cannot be deferred to
whichever number happens to be highest.

---

## Implications for the scoring engine

Stage 2 produced three constraints that Stage 4 has to accommodate.

**EPSS is absent where it would be most useful.** None of the twenty-eight Ubuntu findings
carried an EPSS score. These are recent vulnerabilities, and exploit prediction data lags
disclosure. Treating a missing EPSS value as zero would push the newest findings to the bottom
of the queue, which inverts the intended behaviour.

**Other exploit signals exist and are populated.** The same findings carry
`exploit_available: true` and `exploitability_ease` values. Where EPSS is missing, these are
available as a fallback rather than nothing.

**Patch age is available and underused.** Plugin metadata includes
`patch_publication_date`. Time since a fix became available is a direct measure of exposure and
of remediation performance, and it is present on every finding that has a fix.

---

## Dataset capture

The scanner licence is time limited and its data is not retained after expiry, so the full
dataset was extracted to disk while the licence remained active:

- 4 scan results with complete findings and severity data
- 388 plugin records containing CVE references, CVSS v2 and v3 scores, VPR, exploit
  availability and patch publication dates

Extraction used the REST API's read endpoints, as established in Stage 1. Bulk export is
licence restricted; reading the scan detail endpoint and iterating the vulnerability array is
not.

Subsequent stages operate on this dataset offline and do not depend on a live scanner.

---

## Screenshots

| File | Content |
|---|---|
| `01-aws-uncredentialed-baseline.png` | External scan, no findings above informational |
| `02-aws-credentialed-findings.png` | Authenticated scan, `Auth: Pass`, 21 Critical and High |
| `03-ubuntu-security-findings.png` | The 28 Ubuntu Security Notice findings with CVSS scores |
| `04-curl-finding-detail.png` | Version comparison, CVE list and stated detection method |
| `05-post-remediation-clean.png` | Post-reboot rescan, no findings above informational |

---

## Stage 2 outcome

- Cloud environment built with account-level controls applied before any workload
- Stage 1's authentication finding reproduced on a current, patched, correctly configured host
- A scan failure diagnosed to the network path, with the initial hypothesis disproved by the
  target's own logs
- Full remediation cycle completed and verified on live infrastructure
- Three concrete design constraints identified for the scoring engine
- Dataset captured for offline use in subsequent stages

**Next:** programmatic extraction and normalisation of the captured dataset, then enrichment
against public exploit intelligence.
