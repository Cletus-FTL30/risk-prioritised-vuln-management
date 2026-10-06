# Stage 5: CMDB Integration and Remediation Records

## Objective

Turn a ranked list into assigned work.

Stage 4 produced 292 findings ordered by risk. An ordered list is not a remediation programme.
Someone has to own each item, it has to be attached to an asset, and it has to carry a date by
which it is due. This stage builds that in ServiceNow.

Three decisions carry the stage, and they are the substance of it:

- **Routing**: which team fixes a finding, inferred from what kind of finding it is
- **SLA**: how long they have, derived from risk score rather than severity label
- **Linkage**: which configuration item it belongs to

**Result:** 292 vulnerable item records, each linked to a CMDB asset, assigned to one of three
teams, with a remediation deadline between 7 and 180 days.

---

## Platform

A ServiceNow Personal Developer Instance, which is free and carries the full platform.

ServiceNow's own Vulnerability Response module is a licensed product and is not available on a
developer instance. The schema was therefore designed and built rather than configured, which
is a better exercise: the data model had to be reasoned about rather than inherited.

### Schema

Two CMDB server records were created for the assessed hosts, and a custom table
`u_vulnerable_item` to hold findings.

The table's thirteen columns were created by background script against `sys_dictionary`, the
table that defines every other table's columns. Creating schema by inserting rows into the
platform's own metadata is how ServiceNow works underneath its forms, and it is considerably
faster than thirteen passes through a UI.

| Field | Type | Purpose |
|---|---|---|
| Finding ID | String | Unique key from the pipeline, for idempotency |
| Plugin ID / Name | String | Scanner identity of the vulnerability |
| Severity | String | The scanner's own rating, retained for comparison |
| Risk Score | Decimal | The model's output |
| EPSS Score | Decimal | Exploitation probability |
| KEV | Boolean | Confirmed active exploitation |
| CVEs | String | Identifiers, for cross-reference |
| Host IP | String | Match key to the CMDB |
| Configuration Item | Reference → `cmdb_ci_server` | The asset |
| Assignment Group | Reference → `sys_user_group` | The owner |
| Due Date | Date/Time | Derived deadline |
| Solution | String | Remediation guidance from the scanner |

The two reference fields are what make this a CMDB integration rather than a flat list. A
finding joined to an asset record can be asked about from either direction: what is wrong with
this server, and which servers have this vulnerability.

### A model arrived at twice

ServiceNow's vulnerability module uses a "vulnerable item" as the join between a vulnerability
and an asset: the same CVE on three servers is three vulnerable items, not one vulnerability.

The Stage 3 parser emitted one record per scan, host and plugin for the same reason, before
this table existed. The schema here matches a design the pipeline had already arrived at
independently, which is a reasonable sign the model is the natural one rather than an arbitrary
choice.

---

## Routing

Three assignment groups, reflecting the distinction identified in Stage 2: a missing package
update, a weak credential and an active backdoor are not the same kind of work.

| Group | Owns |
|---|---|
| Platform Engineering | Operating system and package patching |
| Application Support | Application and middleware remediation |
| Security Operations | Configuration weaknesses and suspected compromise |

### The first implementation was wrong

Routing initially matched keywords in the plugin name. An advisory named
`Ubuntu ... : openssl vulnerabilities (USN-8414-1)` matched on `ssl` and was routed to Security
Operations as a configuration problem.

It is not a configuration problem. It is an `apt upgrade`.

The same rules sent `Weak Debian OpenSSH Keys in ~/.ssh/authorized_keys` to Platform
Engineering, because the name contains no word the rules were looking for. That finding genuinely
is a credential problem requiring key regeneration, not a patch.

So the first version had it backwards in both directions, and the dry run showed Ubuntu package
updates scattered across all three teams.

### The fix was better logic, not more keywords

The rules now check **whether a vendor fix exists** before looking at the name:

```
1. Suspected compromise           → Security Operations   (overrides all)
2. Has a USN or patch date        → Platform Engineering  (it is patch work)
3. Credential / config keywords   → Security Operations   (no patch exists)
4. Application or middleware      → Application Support
5. Everything else                → Platform Engineering
```

The ordering is the whole fix. Whether a fix has been published is a fact about the finding;
a keyword in its title is a guess about it. Checking the fact first stops an openssl package
update being misclassified because of three letters in its name.

### Result

| Group | Records |
|---|---|
| Platform Engineering | 269 |
| Security Operations | 22 |
| Application Support | 1 |

The distribution is heavily skewed because both assessed hosts are Linux servers whose findings
are overwhelmingly missing package updates. In an estate with web applications and databases the
balance would differ.

---

## Remediation deadlines

SLA is derived from risk score, not from severity.

| Risk score | Priority | Deadline |
|---|---|---|
| 80+ | Critical | 7 days |
| 60–79 | High | 14 days |
| 40–59 | Moderate | 30 days |
| 20–39 | Low | 90 days |
| under 20 | Planning | 180 days |

The scoring model floors any CISA KEV finding at 80, so **every confirmed-exploited
vulnerability lands in the 7-day band automatically**, whatever its CVSS score says. That is
the intended behaviour: a vulnerability known to be exploited in the wild should not be argued
into a longer deadline by a mediocre severity rating.

### What this produces

| Priority | Deadline | Findings |
|---|---|---|
| Critical | 7 days | 4 |
| High | 14 days | 13 |
| Moderate | 30 days | 49 |
| Low | 90 days | 169 |
| Planning | 180 days | 57 |

**292 findings become 17 things that need attention in the next fortnight.**

That is the entire argument of the project in a single table. Not "here are 292 vulnerabilities",
but "four of these are being actively exploited and need fixing this week, thirteen more within
a fortnight, and the remaining 275 can be scheduled".

A remediation queue nobody can finish gets ignored. A queue of four is work.

---

## Loading the records

The pipeline supports two paths to ServiceNow.

**REST API.** A client against the Table API, creating one record per finding, resolving
assignment groups and configuration items by name rather than by hardcoded sys_id, and skipping
findings already present so that re-running is safe.

Hardcoded sys_ids are the usual reason an integration breaks the moment it is moved to another
instance, so every reference is resolved by lookup.

**CSV and Import Set.** The same records written to CSV and loaded through ServiceNow's import
and transform process: staging table, transform map, field mapping, then transform into the
target table. 292 rows, 292 inserts, 0 errors.

The second path was used. Authentication against the developer instance failed with HTTP 401
despite working credentials, the correct platform REST role, and successful UI login. Rather
than continue debugging instance configuration, the export path was used instead.

Worth recording rather than hiding: the integration logic — routing, SLA derivation, reference
resolution, idempotency — is identical on both paths. What differed was the transport. An
integration that can produce a loadable artefact when its API path is unavailable is more
useful than one that can only do one thing, and building the fallback took less time than
debugging the instance would have.

### Reference resolution

The CSV carries display names (`metasploitable`, `Platform Engineering`) rather than sys_ids.
The transform map resolves these into record references on import, which is why the loaded
records show both fields as links to the CMDB and group records rather than as text.

---

## Credential handling

A dedicated integration user was created rather than using the administrator account, on the
same reasoning as the scanner credentials in Stage 1: an integration that holds administrative
rights on the ticketing system is a privilege escalation path.

The ITIL role granted to it carries 46 inherited roles, which is considerably more than writing
to one table requires. A production integration would use a custom role scoped to the specific
tables it touches.

The instance password is held in a file outside the repository with `600` permissions, read
into the environment at runtime, and never committed. This is the third point in the project
where credential handling has been a design decision rather than an afterthought: scanner SSH
credentials in Stage 1, scanner API keys in Stage 3, and platform credentials here.

---

## Limitations

**The Application Support rule almost never fires.** It matched one finding in 292. The patch
rule is evaluated first and catches nearly everything, because both assessed hosts are Linux
servers whose findings are package updates. The rule is not wrong, but in this environment it
is close to unreachable, and a rule that never fires is not a rule.

**The same vulnerability can route two ways.** Two instances of the Debian OpenSSH/OpenSSL
random number generator weakness were routed to different teams, because one record carried
patch metadata and the other did not. Routing should depend on the vulnerability, not on which
fields happen to be populated for a given instance of it. Deduplicating on plugin identity
before routing would fix this.

**Coalescing is not configured.** The import creates records rather than updating matching ones,
so a second import would duplicate. The API path handles this with a lookup before create; the
import path needs the finding ID marked as a coalesce field to behave the same way.

**The asset inventory is two hosts.** Routing and SLA logic that works across two Linux servers
has not been tested against the variety a real estate contains.

---

## Code

| File | Purpose |
|---|---|
| `src/push_servicenow.py` | Routing, SLA derivation, API client and CSV export |
| `data/vulnerable_items.csv` | 292 records as loaded |

---

## Screenshots

| File | Content |
|---|---|
| `01-servicenow-vulnerable-items.png` | Loaded records sorted by risk score: KEV findings at the top with 7-day deadlines, each linked to a configuration item and an assignment group |

---

## Stage 5 outcome

- CMDB records and a custom vulnerable item schema built on a platform without the licensed
  vulnerability module
- Routing implemented, found to misclassify package updates as configuration work, and
  corrected by checking for a published vendor fix before matching keywords
- SLA derived from risk score, with confirmed exploitation guaranteeing the shortest deadline
- 292 records loaded, each joined to an asset and an owning team
- The queue reduced from 292 findings to 17 requiring attention within a fortnight
- Three limitations identified and documented rather than left for a reader to find

**Next:** reporting. A technical findings report and an executive summary, built from the same
dataset.
