# Stage 6: Reporting

## Objective

Produce the two documents an assessment has to deliver, generated from the dataset rather than
written by hand.

A pipeline that ends at a ticket queue serves the people doing remediation. It does not serve
the person deciding whether to fund it, or the one who has to explain the organisation's
exposure to an auditor. Those are different readers with different questions, and giving them
the same document serves neither.

---

## Two documents, not one with a summary

**The executive summary** answers: what should we do, and what is the risk of not doing it.
One page. No CVE identifiers, no plugin names, no CVSS vectors, no tool names. The reader is
deciding about time and money, not about packages.

**The technical findings report** answers: what exactly is wrong, on which system, in what
order, and how is it fixed. Names, scores, evidence, deadlines, methodology.

The common failure is to write the technical report and bolt an "executive summary" on the
front which is really an abstract of it — same vocabulary, fewer paragraphs. That is still a
technical document, and the reader it was supposedly written for still cannot act on it.

### Both are generated

Both documents are produced by `report.py` from the scored dataset.

This matters for a reason beyond convenience. A report written by hand is accurate on the day
it is written and progressively less so afterwards, and the two documents drift apart from each
other as one is updated and the other is not. Generated reports cannot contradict each other,
and they regenerate on the next scan cycle in seconds.

It also forces the figures to be real. Every number in both documents is computed from the
data, so none of them can be approximate, aspirational, or left over from a previous draft.

---

## What the reports say

### Executive summary

Opens with the position in three sentences:

> An assessment of 2 systems identified **292 distinct security weaknesses**. Of these,
> **17 require action within the next two weeks**. The remainder can be scheduled into normal
> maintenance.
>
> **4 are confirmed as being actively exploited by attackers today**, according to the US
> Cybersecurity and Infrastructure Security Agency. These are not theoretical weaknesses.
> Working attacks exist and are in use.

Then explains why the number is 17 and not 292, in language that does not require knowing what
EPSS is:

> Security tools rate weaknesses by how much damage they could cause if exploited. That is only
> half the question. The other half is whether anyone is actually exploiting them.
>
> This assessment combines both. The result is that of 139 findings the scanner rated as
> Critical or High, **86 present little practical risk** and can safely be scheduled rather
> than rushed.
>
> That matters because a remediation list nobody can finish gets ignored. A list of 17 items
> gets done.

And identifies the root cause rather than listing symptoms:

> **91% of all findings sit on a single system** running software that is no longer supported
> by its vendor and receives no security updates. Patching its findings individually is not
> possible. The system needs rebuilding on a supported platform. Doing so resolves the majority
> of this report in one action.

That last point is the one most reports miss. 292 findings presented as 292 items of work
obscures the single decision that removes most of them.

### Technical findings report

Scope and method, severity summary, per-system breakdown, confirmed exploitation, the ordered
priority queue with deadlines, where severity ranking would misdirect effort, exposure
duration, the remediation schedule, and the scoring methodology.

Two sections are worth drawing out.

**Per-system, the report calls out its own most interesting case:**

> **vuln-lab-ubuntu** carries 21 findings rated Critical or High but none requiring urgent
> action. Its findings are recent vendor patches for which no exploitation has been observed or
> predicted. This is the case the risk model exists to distinguish: a high severity count is
> not the same as a high risk.

A severity-based report would present that host as the more urgent of the two. It is not.

Deadlines are stated relative to the assessment ("7 days", "14 days") rather than as calendar
dates. The dates themselves live on the tracked records from Stage 5, where they are anchored to
when the finding was raised. Restating them in a document that regenerates would let the report
and the records disagree the moment either one was rebuilt.

**Exposure duration** reports a metric most vulnerability reports omit entirely:

| | |
|---|---|
| Median time since a fix was published | 15.7 years |
| Oldest | 18.4 years |
| Fix available over 10 years | 235 findings |

Patch age measures how long a known weakness has gone unaddressed. A programme closing findings
faster than new ones appear still has a problem if the oldest are never touched, and a count of
open findings will not show it. This is also the figure that makes the end-of-life argument
without needing to make it: a median of nearly sixteen years is not a patching backlog, it is a
platform decision.

---

## Figures

| | |
|---|---|
| Systems assessed | 2 |
| Raw findings | 623 |
| Distinct vulnerability-host pairs | 292 |
| Carrying a CVE identifier | 245 (84%) |
| Scored for exploitation likelihood | 245 (84%) |
| Confirmed actively exploited | 4 |
| Requiring action within 14 days | 17 |
| Rated Critical or High but scoring below 40 | 86 |

| System | Findings | Critical + High | Actively exploited | Urgent |
|---|---|---|---|---|
| metasploitable | 265 | 118 | 4 | 17 |
| vuln-lab-ubuntu | 27 | 21 | 0 | 0 |

---

## Limitations

**One assessment, no trend.** Both reports describe a point in time. The figures that matter
operationally are directional: is the median patch age falling, are findings closing within
their SLA, is the urgent queue shrinking. Those need several cycles, and this project has one.

**SLA compliance is not reported.** The records carry due dates but nothing tracks whether they
were met. Measuring a remediation programme means measuring the dates, not just setting them.

**The executive summary's root-cause finding is specific to this data.** It fires when one
system holds more than 60% of findings. That heuristic works here, where one host is an
end-of-life system holding 91%, but a flatter distribution would need a different analysis to
find the pattern worth reporting.

---

## Code

| File | Purpose |
|---|---|
| `src/report.py` | Generates both reports from the scored dataset |
| `reports/executive-summary.md` | One page, for the decision |
| `reports/technical-findings-report.md` | Full detail, for the work |

---

## Stage 6 outcome

- Two reports written for two different readers, generated from a single dataset so they cannot
  disagree or go stale separately
- Every figure computed from the data rather than written by hand
- Root cause surfaced in place of a symptom count: 91% of findings traced to one unsupported
  system, resolvable by one decision
- Exposure duration reported as a remediation performance measure, at a median of 15.7 years
- The case where severity and risk disagree called out explicitly, including the host that
  looks worse by severity and is not

---

## Project complete

Six stages, from a scanner on an isolated network to two reports built on live exploit
intelligence.

| Stage | Output |
|---|---|
| 1. Scanning baseline | 95% of High-severity findings invisible without credentials |
| 2. Cloud assessment | 21 Critical and High on a newly launched, patched instance |
| 3. Extraction and enrichment | 623 findings, 808 CVEs enriched against EPSS and KEV |
| 4. Risk scoring | POODLE moves from rank 281 to 38; a Critical falls from 2 to 94 |
| 5. CMDB and ticketing | 292 records assigned and dated; 17 urgent |
| 6. Reporting | Executive and technical reports, generated |
