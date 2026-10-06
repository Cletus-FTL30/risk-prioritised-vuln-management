# Stage 4: Risk Scoring Model

## Objective

Produce a prioritisation that reflects likelihood of exploitation and business context, not
just theoretical impact, and measure how far it differs from ranking by severity.

Stages 1 to 3 established the problem with evidence: a Low-severity finding carrying the maximum
EPSS score, Critical findings two orders of magnitude less likely to be exploited, and signal
coverage too sparse for any single input to carry a ranking. This stage builds a model that
responds to those constraints and tests whether it changes the queue.

---

## The model

```
risk = (0.4 x impact + 0.6 x likelihood) x asset_multiplier
```

A weighted sum rather than a product, so neither term can collapse the other to zero.
Likelihood carries the larger coefficient, which is the project's argument expressed as a
number: how probable exploitation is matters more than how severe it would theoretically be.

### Likelihood, in tiers

| Evidence | Value | Basis |
|---|---|---|
| CISA KEV listing | 1.00 | Exploitation observed in the wild |
| EPSS score | the score | Measured prediction from FIRST |
| Exploit available flag | 0.50 | Exploit code exists, probability unmeasured |
| No evidence | 0.15 | Neutral, recorded, never zero |

The bottom row is the one that required thought. Over half the dataset carries no CVE, so no
CVE-keyed source can score it. Treating that as zero would rank a weak credential the scanner
proved by logging in below a vulnerability nobody has ever exploited. A neutral value keeps
these findings in contention, and the tier used is recorded on every finding so the absence
stays visible.

### Impact, with an explicit fallback chain

CVSS v3 where present, otherwise v2, otherwise derived from the scanner's severity rating.

v3 covers 9.2% of the scored findings and v2 covers 80.1%. A model requiring v3 would discard
most of the dataset. The two use different scales, so the source is recorded alongside the
value rather than the fallback happening silently.

The severity-derived tier matters for the same reason as the unknown likelihood tier: it keeps
configuration weaknesses and service findings, which have no CVSS at all, inside the ranking
rather than dropping them to the floor.

### Asset context

The only input a scanner cannot supply. Criticality and exposure are applied as separate
multipliers rather than combined into one rating, because a business-critical system on an
isolated network and a trivial one on the public internet are different problems and a single
combined number hides which is which.

In this project the inventory is a JSON file. In an enterprise it would be the CMDB.

### Confirmed outranks predicted

A finding on the CISA KEV catalogue cannot score below 80, whatever else is missing or low.

This matters in practice. One KEV finding in this dataset carries an EPSS of 0.1447, which the
model would otherwise rank as unremarkable. EPSS predicts; CISA observes. Where the two
disagree, the observation wins. That is a deliberate design choice rather than a tuning
artefact, and it is worth stating because a reader will otherwise wonder why a low-EPSS finding
sits at rank 2.

---

## Asset weighting swamped the evidence

The first configuration used criticality weights from 0.6 to 1.5 and exposure weights from 0.7
to 1.3. Across the two assets in this environment that produced a 3.7x spread between the
internet-facing cloud host and the isolated lab host.

The result contradicted the model's own purpose. Ranks 5 to 15 were filled with findings
carrying no EPSS data at all, scoring between 60 and 74 purely on asset weighting, while the
highest-EPSS finding in the dataset sat at rank 59.

Business context had overwhelmed vulnerability evidence. The model was ranking by which host a
finding sat on, with the vulnerability itself as a tiebreaker.

Narrowing the ranges to 0.85 to 1.2 for criticality and 0.9 to 1.15 for exposure reduced the
spread to 1.65x, and the ordering corrected itself.

| | First configuration | Second configuration |
|---|---|---|
| Asset spread | 3.7x | 1.65x |
| Ranks 5 to 15 | no EPSS data | all EPSS above 0.70 |
| POODLE (EPSS 1.0000) | rank 59 | rank 38 |
| ISC BIND (EPSS 0.9342) | rank 41 | rank 15 |

Both configurations are retained in the repository. The finding is not that the first set of
numbers was wrong; it is that a risk model's output is sensitive to weights that are chosen
rather than measured, and that sensitivity has to be tested rather than assumed. A model shipped
on its first configuration would have produced a confident ranking that undermined the argument
it was built to make.

---

## Evidence quality

Before trusting the ranking, it is worth knowing what the scores actually rest on. A model that
degrades through tiers is only defensible if you can say how often each tier was reached.

**Likelihood**

| Tier | Findings | Share |
|---|---|---|
| EPSS | 241 | 82.5% |
| No evidence | 46 | 15.8% |
| CISA KEV | 4 | 1.4% |
| Exploit available | 1 | 0.3% |

**Impact**

| Source | Findings | Share |
|---|---|---|
| CVSS v2 | 234 | 80.1% |
| Severity derived | 31 | 10.6% |
| CVSS v3 | 27 | 9.2% |

82.5% of likelihood scores rest on measured EPSS values, so the ranking is mostly driven by
data rather than defaults. The 15.8% falling through to the neutral tier are visible and
identifiable rather than silently assumed.

The impact figures are less comfortable. Four out of five scores come from CVSS v2, a standard
superseded in 2015. That is a property of the environment being assessed rather than a flaw in
the model, but it means impact is the weaker half of the calculation here.

---

## Results

292 distinct vulnerability and host pairs, after excluding 298 informational findings that are
not remediation work.

### Ranked by severity, as most tools default

Every entry in the top 15 is Critical. Their EPSS scores range from 0.0186 to 0.7437, with no
relationship to their position. The ordering within the band is effectively arbitrary.

### Ranked by the model

| Rank | Severity | Risk | EPSS | KEV | Finding |
|---|---|---|---|---|---|
| 1 | High | 80.0 | 1.0000 | yes | Ubuntu kernel vulnerabilities |
| 2 | Critical | 80.0 | 0.1447 | yes | Ubuntu package vulnerabilities |
| 3 | Critical | 80.0 | 1.0000 | yes | Bash Remote Code Execution (Shellshock) |
| 4 | Critical | 80.0 | 0.9927 | yes | Apache Tomcat AJP Connector Request Injection |
| 5 | High | 69.2 | 0.9883 | | Ubuntu apache2 vulnerabilities |
| 6 | High | 66.4 | 0.9470 | | SSL Medium Strength Cipher Suites (SWEET32) |
| 7 | Critical | 64.7 | 0.7437 | | Ubuntu samba vulnerabilities |
| 8 | Critical | 63.1 | 0.7072 | | Debian OpenSSH/OpenSSL random number generator |
| 15 | Medium | 60.9 | 0.9342 | | ISC BIND denial of service |

The four confirmed-exploited findings take the top four positions. Everything from rank 5 to 15
carries an EPSS above 0.70. A Medium-severity finding sits at rank 15, above dozens of
Criticals.

### What moved

**Promoted**

| Severity rank | Risk rank | Severity | EPSS | Finding |
|---|---|---|---|---|
| 281 | 38 | Low | 1.0000 | SSLv3 Padding Oracle (POODLE) |
| 276 | 31 | Low | 0.9986 | SSL/TLS EXPORT_DHE 512-bit ciphers |
| 266 | 26 | Medium | 0.9869 | SSL/TLS EXPORT_RSA 512-bit ciphers |
| 217 | 18 | Medium | 0.9650 | Ubuntu package vulnerabilities |
| 201 | 15 | Medium | 0.9342 | ISC BIND denial of service |

**Demoted**

| Severity rank | Risk rank | Severity | EPSS | Finding |
|---|---|---|---|---|
| 2 | 94 | Critical | 0.0568 | Ubuntu kernel vulnerabilities |
| 10 | 105 | Critical | 0.0186 | Ubuntu apt vulnerabilities |
| 49 | 149 | High | 0.0240 | Ubuntu kernel module vulnerabilities |
| 107 | 215 | High | 0.0040 | Ubuntu package vulnerabilities |

Thirteen High-severity kernel findings fall into the 149 to 215 range on EPSS scores below 0.05.

POODLE moves 243 places. A Critical finding falls 92 places. Under severity ordering an engineer
clears 280 findings before reaching a vulnerability the model rates as certain to be exploited.

---

## Where the model falls short

Stage 3 set five constraints. Four are satisfied. The fifth is not, and the gap is visible in
the output.

**Confirmed should outrank inferred.** The model implements this for CISA KEV, but not for
findings the scanner itself demonstrated.

The weak VNC password identified in Stage 1 ranks first under severity ordering and scores 37.5
under the model, outside the top 50. The scanner did not infer this finding from a version
string; it authenticated to the service and recorded that it had done so. It is the single most
certain finding in the dataset.

It scores poorly because it has no CVE, therefore no EPSS, therefore the neutral likelihood tier
of 0.15. The model treats a demonstrated weakness as less likely to be exploited than a
predicted one.

The fix is available in data already captured. Plugin records carry an attribute indicating the
scanner confirmed exploitation, which was not extracted in Stage 3's parser. Adding it as a
likelihood tier above EPSS and below KEV would resolve the gap, and is the first change this
model needs.

Naming it matters more than fixing it immediately. A scoring model's limitations determine where
human review is still required, and a model presented without them invites more trust than it
has earned.

---

## Other limitations

**Asset weights are judgement, not measurement.** The inventory values were chosen, and the
preceding section shows how much the ranking depends on them. In an organisation these would
come from a CMDB with business owners accountable for the ratings, which makes them
contestable rather than arbitrary.

**Instance count is ignored.** A vulnerability present on one host and on fifty scores the same.
Across a real estate that distinction matters.

**Patch age is calculated but unused.** Days since a fix became available is recorded on every
finding and feeds nothing. It is a direct measure of exposure duration and belongs in either the
score or the remediation SLA.

**EPSS is a 30-day forecast.** A score of 0.02 does not mean safe, it means unlikely within a
month. Treating low EPSS as permission to ignore a vulnerability indefinitely would be a
misreading of the input.

---

## Code

| File | Purpose |
|---|---|
| `src/score.py` | The scoring model, with every intermediate value retained |
| `assets.json` | Asset inventory and weighting configuration |
| `data/scored.json` | Findings scored under the first configuration |
| `data/scored-v2.json` | Findings scored under the corrected configuration |

Every score carries its full working: the impact value and its source, the likelihood value and
its tier, the asset multiplier, and whether the KEV floor was applied. A score an analyst cannot
interrogate is one they will not act on, and in a ticketing pipeline an unexplained number is
the fastest route to the whole system being ignored.

---

## Screenshots

| File | Content |
|---|---|
| `01-severity-vs-risk.png` | Both rankings side by side, with the evidence breakdown |
| `02-rank-movement.png` | Findings promoted and demoted, with position changes |

---

## Stage 4 outcome

- A scoring model combining impact, likelihood and asset context, degrading explicitly through
  tiers where signals are absent
- Asset weighting identified as dominating the ranking, measured, and corrected
- 292 distinct findings ranked, with every score fully auditable
- Reordering quantified: a Low-severity finding with maximum exploitation probability moves from
  rank 281 to 38, while a Critical finding at EPSS 0.0568 falls from rank 2 to 94
- One unsatisfied design constraint identified and documented, with the remedy specified

**Next:** matching findings to asset records and generating remediation tickets with assignment
and SLA derived from the risk score.
