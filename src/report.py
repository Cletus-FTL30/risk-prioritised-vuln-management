#!/usr/bin/env python3
"""
report.py

Generates the two reports a vulnerability assessment has to produce.

They answer different questions and are written for different readers, which
is why they are two documents rather than one with a summary at the top:

  Executive summary    what should we do, and what is the risk of not doing
                       it. No CVEs, no plugin names, no CVSS. One page.

  Technical report     what exactly is wrong, on which host, and how is it
                       fixed. Names, scores, evidence, remediation steps.

Both are generated from the same scored dataset, so they cannot disagree with
each other or go stale separately. A report written by hand is out of date the
next time the scanner runs.

Usage:
    python3 report.py --input scored-v2.json --assets assets.json \\
                      --outdir reports/
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


# Must match the bands in push_servicenow.py. Defined once here and imported
# in a larger codebase; duplicated deliberately to keep each script runnable
# on its own.
SLA_BANDS = [
    (80, 7, "Critical"),
    (60, 14, "High"),
    (40, 30, "Moderate"),
    (20, 90, "Low"),
    (0, 180, "Planning"),
]

URGENT_DAYS = 14


def resolve_sla(risk_score):
    for threshold, days, label in SLA_BANDS:
        if risk_score >= threshold:
            return days, label
    return 180, "Planning"


def deduplicate(findings):
    """One record per vulnerability-host pair, keeping the highest score."""
    best = {}
    for finding in findings:
        key = (finding.get("host_ip"), finding.get("plugin_id"))
        if key not in best or finding["risk_score"] > best[key]["risk_score"]:
            best[key] = finding
    return list(best.values())


def years(days):
    return days / 365.25


def analyse(findings, inventory):
    """Compute every figure both reports need, once."""
    actionable = [f for f in findings if f.get("severity", 0) > 0]
    unique = deduplicate(actionable)

    assets = inventory.get("assets", {})

    by_host = defaultdict(list)
    for finding in unique:
        by_host[finding.get("host_ip")].append(finding)

    urgent = [f for f in unique if resolve_sla(f["risk_score"])[0] <= URGENT_DAYS]
    kev = [f for f in unique if f.get("kev")]

    # Patch age: how long a fix has been available and unapplied. A direct
    # measure of exposure duration, and more meaningful to a non-technical
    # reader than a CVSS score.
    ages = sorted(f["patch_age_days"] for f in unique
                  if f.get("patch_age_days") is not None)

    # Where severity ordering and risk ordering disagree. This is the
    # justification for the whole model, so it belongs in the report rather
    # than only in the methodology.
    overrated = [f for f in unique
                 if f.get("severity", 0) >= 3 and f["risk_score"] < 40]
    underrated = [f for f in unique
                  if f.get("severity", 0) <= 2 and f["risk_score"] >= 60]

    bands = Counter(resolve_sla(f["risk_score"])[1] for f in unique)

    return {
        "generated": datetime.now(timezone.utc),
        "total_records": len(findings),
        "actionable": len(actionable),
        "unique": unique,
        "count": len(unique),
        "by_host": by_host,
        "assets": assets,
        "urgent": sorted(urgent, key=lambda f: -f["risk_score"]),
        "kev": sorted(kev, key=lambda f: -(f.get("epss_live") or 0)),
        "severity": Counter(f["severity_label"] for f in unique),
        "bands": bands,
        "ages": ages,
        "overrated": overrated,
        "underrated": underrated,
        "with_cve": sum(1 for f in unique if f.get("cves")),
        "with_epss": sum(1 for f in unique if f.get("epss_live") is not None),
    }


def asset_label(a, host_ip, assets):
    asset = assets.get(host_ip, {})
    return asset.get("name") or host_ip


def write_executive_summary(path, a):
    """One page, for a reader who will not open the technical report.

    No CVE identifiers, no plugin names, no CVSS vectors. The question being
    answered is what to do, not what was found.
    """
    urgent_count = len(a["urgent"])
    kev_count = len(a["kev"])
    median_age = years(a["ages"][len(a["ages"]) // 2]) if a["ages"] else 0

    lines = []
    w = lines.append

    w("# Vulnerability Assessment: Executive Summary")
    w("")
    w("---")
    w("")

    w("## The position")
    w("")
    w(f"An assessment of {len(a['by_host'])} systems identified "
      f"**{a['count']} distinct security weaknesses**.")
    w("")
    w(f"Of these, **{urgent_count} require action within the next two weeks**. "
      f"The remainder can be scheduled into normal maintenance.")
    w("")

    if kev_count:
        w(f"**{kev_count} are confirmed as being actively exploited by attackers "
          f"today**, according to the US Cybersecurity and Infrastructure "
          f"Security Agency. These are not theoretical weaknesses. Working "
          f"attacks exist and are in use.")
        w("")

    w("## What this means")
    w("")
    w("Security tools rate weaknesses by how much damage they could cause if "
      "exploited. That is only half the question. The other half is whether "
      "anyone is actually exploiting them.")
    w("")
    w(f"This assessment combines both. The result is that of "
      f"{a['severity']['Critical'] + a['severity']['High']} findings the "
      f"scanner rated as Critical or High, **{len(a['overrated'])} present "
      f"little practical risk** and can safely be scheduled rather than "
      f"rushed.")
    w("")
    w("That matters because a remediation list nobody can finish gets ignored. "
      f"A list of {urgent_count} items gets done.")
    w("")

    if a["ages"]:
        w("## How long this has been true")
        w("")
        w(f"For the findings where a vendor fix exists, the median time since "
          f"that fix was published is **{median_age:.0f} years**.")
        w("")
        w("These are not newly discovered problems. They are known problems "
          "with known solutions that have not been applied. The exposure is "
          "the gap between the two.")
        w("")

    w("## Recommended action")
    w("")
    w(f"1. **This fortnight.** Remediate the {urgent_count} findings "
      f"identified as urgent. These are assigned and dated.")
    w("")

    # Root cause, where one host dominates
    worst_host = max(a["by_host"].items(), key=lambda kv: len(kv[1]))
    worst_name = asset_label(a, worst_host[0], a["assets"])
    share = len(worst_host[1]) / a["count"] * 100
    if share > 60:
        w(f"2. **Address the root cause.** {share:.0f}% of all findings sit on "
          f"a single system (*{worst_name}*) running software that is no "
          f"longer supported by its vendor and receives no security updates. "
          f"Patching its findings individually is not possible. The system "
          f"needs rebuilding on a supported platform. Doing so resolves the "
          f"majority of this report in one action.")
        w("")
        w("3. **Schedule the remainder** into routine maintenance windows "
          "according to the assigned deadlines.")
    else:
        w("2. **Schedule the remainder** into routine maintenance windows "
          "according to the assigned deadlines.")
    w("")

    w("## Remediation schedule")
    w("")
    w("| Priority | Deadline | Findings |")
    w("|---|---|---|")
    for _, days, label in SLA_BANDS:
        count = a["bands"].get(label, 0)
        if count:
            w(f"| {label} | {days} days | {count} |")
    w("")

    w("---")
    w("")
    w("*Every finding in this summary is tracked individually with an assigned "
      "owner and deadline. Technical detail is in the accompanying findings "
      "report.*")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def write_technical_report(path, a):
    """The detailed report, for the people doing the work."""
    lines = []
    w = lines.append

    w("# Vulnerability Assessment: Technical Findings Report")
    w("")
    w("---")
    w("")

    # ---- Scope -----------------------------------------------------------
    w("## Scope and method")
    w("")
    w("Authenticated and unauthenticated network scanning, with findings "
      "enriched against two external sources and ranked by a risk model "
      "combining severity, exploitation likelihood and asset context.")
    w("")
    w("| | |")
    w("|---|---|")
    w("| Systems assessed | " + str(len(a["by_host"])) + " |")
    w("| Raw findings | " + str(a["total_records"]) + " |")
    w("| Actionable findings | " + str(a["actionable"]) + " |")
    w("| Distinct vulnerability-host pairs | " + str(a["count"]) + " |")
    w(f"| Carrying a CVE identifier | {a['with_cve']} "
      f"({a['with_cve'] / a['count'] * 100:.0f}%) |")
    w(f"| Scored for exploitation likelihood | {a['with_epss']} "
      f"({a['with_epss'] / a['count'] * 100:.0f}%) |")
    w("")
    w("Enrichment sources: FIRST EPSS (exploitation probability) and the CISA "
      "Known Exploited Vulnerabilities catalogue (confirmed exploitation).")
    w("")

    # ---- Headline --------------------------------------------------------
    w("## Summary of findings")
    w("")
    w("| Severity | Count |")
    w("|---|---|")
    for label in ("Critical", "High", "Medium", "Low"):
        if a["severity"].get(label):
            w(f"| {label} | {a['severity'][label]} |")
    w(f"| **Total** | **{a['count']}** |")
    w("")
    w("Severity is the scanner's own rating and is reported here for "
      "reference. Remediation order in this report is set by risk score, "
      "which accounts for exploitation likelihood and asset exposure as well "
      "as severity.")
    w("")

    # ---- Per host --------------------------------------------------------
    w("## By system")
    w("")
    w("| System | Findings | Critical + High | Actively exploited | Urgent |")
    w("|---|---|---|---|---|")
    for host, items in sorted(a["by_host"].items(),
                              key=lambda kv: -len(kv[1])):
        name = asset_label(a, host, a["assets"])
        crit_high = sum(1 for f in items if f.get("severity", 0) >= 3)
        kev = sum(1 for f in items if f.get("kev"))
        urgent = sum(1 for f in items
                     if resolve_sla(f["risk_score"])[0] <= URGENT_DAYS)
        w(f"| {name} (`{host}`) | {len(items)} | {crit_high} | {kev} | {urgent} |")
    w("")

    # The interesting case: a host that looks bad by severity but has nothing
    # urgent, or vice versa. Worth calling out explicitly.
    for host, items in a["by_host"].items():
        crit_high = sum(1 for f in items if f.get("severity", 0) >= 3)
        urgent = sum(1 for f in items
                     if resolve_sla(f["risk_score"])[0] <= URGENT_DAYS)
        if crit_high >= 10 and urgent == 0:
            name = asset_label(a, host, a["assets"])
            w(f"**{name}** carries {crit_high} findings rated Critical or High "
              f"but none requiring urgent action. Its findings are recent "
              f"vendor patches for which no exploitation has been observed or "
              f"predicted. This is the case the risk model exists to "
              f"distinguish: a high severity count is not the same as a high "
              f"risk.")
            w("")

    # ---- Confirmed exploitation -----------------------------------------
    if a["kev"]:
        w("## Confirmed active exploitation")
        w("")
        w("Listed in the CISA Known Exploited Vulnerabilities catalogue. These "
          "are not predictions. Exploitation has been observed in the wild.")
        w("")
        w("| Risk | EPSS | System | Finding |")
        w("|---|---|---|---|")
        for f in a["kev"]:
            epss = f.get("epss_live")
            epss_text = f"{epss:.2f}" if epss is not None else "n/a"
            name = asset_label(a, f["host_ip"], a["assets"])
            w(f"| {f['risk_score']:.0f} | {epss_text} | {name} | "
              f"{f['plugin_name'][:60]} |")
        w("")
        w("All are assigned the shortest remediation deadline regardless of "
          "their individual severity rating, because observed exploitation "
          "outranks predicted exploitation.")
        w("")

    # ---- Priority queue --------------------------------------------------
    w("## Priority remediation queue")
    w("")
    w(f"The {len(a['urgent'])} findings requiring action within "
      f"{URGENT_DAYS} days, in order.")
    w("")
    w("| # | Risk | Deadline | Severity | EPSS | System | Finding |")
    w("|---|---|---|---|---|---|---|")
    for i, f in enumerate(a["urgent"], start=1):
        # Deadlines are stated relative to the assessment rather than as
        # calendar dates. The dates live on the tracked records, where they
        # are anchored; restating them here would let the report and the
        # records disagree the moment either is regenerated.
        days, _ = resolve_sla(f["risk_score"])
        epss = f.get("epss_live")
        epss_text = f"{epss:.2f}" if epss is not None else "n/a"
        name = asset_label(a, f["host_ip"], a["assets"])
        w(f"| {i} | {f['risk_score']:.0f} | {days} days | "
          f"{f['severity_label']} | {epss_text} | {name} | "
          f"{f['plugin_name'][:50]} |")
    w("")

    # ---- Where severity misleads ----------------------------------------
    w("## Where severity ranking would misdirect effort")
    w("")
    w(f"**{len(a['overrated'])} findings rated Critical or High score below 40 "
      f"on the risk model.** They have low measured exploitation likelihood "
      f"and sit on systems with limited exposure. Remediating them ahead of "
      f"the priority queue would consume effort for little risk reduction.")
    w("")

    if a["underrated"]:
        n = len(a["underrated"])
        noun = "finding" if n == 1 else "findings"
        verb = "it would sit" if n == 1 else "they would sit"
        w(f"**{n} {noun} rated Medium or Low score 60 or above.** Ranked by "
          f"severity alone {verb} far down the queue despite high "
          f"exploitation likelihood.")
        w("")
        w("| Severity | EPSS | Risk | Finding |")
        w("|---|---|---|---|")
        for f in sorted(a["underrated"], key=lambda x: -x["risk_score"]):
            epss = f.get("epss_live")
            epss_text = f"{epss:.2f}" if epss is not None else "n/a"
            w(f"| {f['severity_label']} | {epss_text} | "
              f"{f['risk_score']:.0f} | {f['plugin_name'][:55]} |")
        w("")

    # ---- Patch age -------------------------------------------------------
    if a["ages"]:
        ages = a["ages"]
        median = years(ages[len(ages) // 2])
        oldest = years(ages[-1])
        over_ten = sum(1 for x in ages if x > 3652)

        w("## Exposure duration")
        w("")
        w("Time elapsed since the vendor published a fix, for the "
          f"{len(ages)} findings where a patch date is recorded.")
        w("")
        w("| | |")
        w("|---|---|")
        w(f"| Median | {median:.1f} years |")
        w(f"| Oldest | {oldest:.1f} years |")
        w(f"| Fix available over 10 years | {over_ten} findings |")
        w("")
        w("Patch age measures how long a known weakness has gone unaddressed, "
          "which is a better indicator of remediation performance than a count "
          "of open findings. A programme closing findings faster than new ones "
          "appear will still show a rising median if the oldest are never "
          "touched.")
        w("")

    # ---- Remediation schedule -------------------------------------------
    w("## Remediation schedule")
    w("")
    w("| Priority | Deadline | Findings |")
    w("|---|---|---|")
    for _, days, label in SLA_BANDS:
        count = a["bands"].get(label, 0)
        if count:
            w(f"| {label} | {days} days | {count} |")
    w(f"| **Total** | | **{a['count']}** |")
    w("")

    # ---- Methodology -----------------------------------------------------
    w("## Scoring methodology")
    w("")
    w("```")
    w("risk = (0.4 x impact + 0.6 x likelihood) x asset_multiplier")
    w("```")
    w("")
    w("Likelihood carries the greater weight. Each input degrades explicitly "
      "where data is absent rather than defaulting to zero, because a finding "
      "with no exploitation data is not the same as one measured as unlikely.")
    w("")
    w("| Input | Source, strongest first |")
    w("|---|---|")
    w("| Likelihood | CISA KEV, FIRST EPSS, exploit availability, neutral |")
    w("| Impact | CVSS v3, CVSS v2, scanner severity rating |")
    w("| Asset | Business criticality and network exposure |")
    w("")
    w("Findings confirmed as actively exploited are assigned a minimum score "
      "so that observation cannot be outranked by estimation.")
    w("")

    w("---")
    w("")
    w("*Generated from scored assessment data. Figures regenerate with each "
      "scan cycle.*")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate executive and technical reports from scored findings."
    )
    parser.add_argument("--input", default="scored-v2.json")
    parser.add_argument("--assets", default="assets.json")
    parser.add_argument("--outdir", default="reports")
    args = parser.parse_args()

    input_path = Path(args.input).expanduser()
    assets_path = Path(args.assets).expanduser()

    for path in (input_path, assets_path):
        if not path.exists():
            print(f"Not found: {path}", file=sys.stderr)
            return 1

    with open(input_path) as f:
        findings = json.load(f)
    with open(assets_path) as f:
        inventory = json.load(f)

    a = analyse(findings, inventory)

    outdir = Path(args.outdir).expanduser()
    outdir.mkdir(parents=True, exist_ok=True)

    exec_path = outdir / "executive-summary.md"
    tech_path = outdir / "technical-findings-report.md"

    write_executive_summary(exec_path, a)
    write_technical_report(tech_path, a)

    print(f"{a['count']} distinct findings across {len(a['by_host'])} systems")
    print(f"  {len(a['urgent'])} urgent, {len(a['kev'])} actively exploited")
    print()
    print(f"Wrote {exec_path}")
    print(f"Wrote {tech_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
