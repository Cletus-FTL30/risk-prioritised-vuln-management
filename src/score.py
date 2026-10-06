#!/usr/bin/env python3
"""
score.py

Ranks findings by risk rather than by severity.

Severity describes how bad a vulnerability would be if exploited. It says
nothing about whether anyone is exploiting it, or whether the affected system
matters. Ranking by severity alone produces a queue where a Low-severity
finding with a 100% exploitation probability sits below thirty-seven Criticals,
some of which are two orders of magnitude less likely to be exploited.

This model combines four things:

    risk = (0.4 x impact + 0.6 x likelihood) x asset_multiplier

  impact      how bad, from CVSS with an explicit fallback chain
  likelihood  how probable, from KEV and EPSS with tiered degradation
  asset       business context, supplied by an inventory, not the scanner

Likelihood carries more weight than impact. That is the argument of the whole
project, expressed as a coefficient.

Stage 3 established five constraints this model has to satisfy, and each is
handled explicitly below:

  1. No signal covers more than 47% of findings, so every input degrades.
  2. A missing signal is never treated as zero.
  3. CVSS v2 and v3 are not mixed silently; the source is recorded.
  4. Findings with no CVE stay rankable.
  5. Confirmed exploitation outranks predicted exploitation.

Usage:
    python3 score.py --input enriched.json --assets assets.json \\
                     --output scored.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


# Weighting between how bad and how likely. Likelihood dominates deliberately.
IMPACT_WEIGHT = 0.4
LIKELIHOOD_WEIGHT = 0.6

# Likelihood values for each tier of evidence, strongest first.
LIKELIHOOD_KEV = 1.00          # observed in the wild, not predicted
LIKELIHOOD_EXPLOIT_FLAG = 0.50  # exploit code exists, probability unknown
LIKELIHOOD_UNKNOWN = 0.15       # no evidence either way

# A finding on the KEV catalogue cannot score below this, whatever else is
# missing. Active exploitation is not something a low CVSS score should be able
# to argue down.
KEV_FLOOR = 80.0

# Impact fallback when no CVSS score exists at all. Derived from the scanner's
# own severity rating, which is present on every finding.
SEVERITY_IMPACT = {
    4: 9.5,   # Critical
    3: 7.5,   # High
    2: 5.0,   # Medium
    1: 2.5,   # Low
    0: 0.0,   # Informational
}


def resolve_impact(finding):
    """Determine impact on a 0-10 scale, recording which source was used.

    CVSS v3 covers 8.2% of this dataset and v2 covers 47.2%, so a model
    requiring v3 would discard most findings. The two use different scales, so
    falling back between them silently would be comparing unlike numbers. The
    source is recorded alongside the value so the mixing stays visible.

    Where neither exists, the scanner's severity rating is mapped to an
    approximate score. That keeps configuration findings and service
    weaknesses, which have no CVSS at all, inside the ranking.
    """
    v3 = finding.get("cvss3_base_score")
    if v3 is not None:
        return v3, "cvss_v3"

    v2 = finding.get("cvss_base_score")
    if v2 is not None:
        return v2, "cvss_v2"

    severity = finding.get("severity", 0)
    return SEVERITY_IMPACT.get(severity, 0.0), "severity_derived"


def resolve_likelihood(finding):
    """Determine likelihood on a 0-1 scale, recording which tier applied.

    The tiers run from observation to absence:

      KEV           CISA has confirmed exploitation in the wild
      EPSS          a measured probability from FIRST's model
      exploit flag  exploit code is known to exist
      unknown       no evidence available

    The unknown case is the important one. Over half of these findings carry no
    CVE, so no CVE-keyed source can score them. Treating that as zero would
    rank a vulnerability the scanner demonstrated by logging in below one that
    nobody has ever exploited. A neutral value is used instead, and flagged, so
    the absence is visible rather than silently decisive.
    """
    if finding.get("kev"):
        return LIKELIHOOD_KEV, "cisa_kev"

    epss = finding.get("epss_live")
    if epss is None:
        epss = finding.get("epss_score")
    if epss is not None:
        return epss, "epss"

    if finding.get("exploit_available") in (True, "true", "True"):
        return LIKELIHOOD_EXPLOIT_FLAG, "exploit_available"

    return LIKELIHOOD_UNKNOWN, "no_evidence"


def resolve_asset(finding, inventory):
    """Look up business context for the affected host.

    This is the only input the scanner cannot provide. Everything else in the
    model describes the vulnerability; this describes what it is attached to.
    """
    host = finding.get("host_ip")
    assets = inventory.get("assets", {})
    return assets.get(host, inventory.get("default_asset", {}))


def asset_multiplier(asset, inventory):
    """Convert asset attributes into a single multiplier.

    Criticality and exposure are applied separately rather than averaged. A
    business-critical system on an isolated network and a trivial one on the
    public internet are different problems, and a single combined rating would
    hide which is which.
    """
    criticality = str(asset.get("criticality", 3))
    exposure = asset.get("exposure", "internal")

    crit_weight = inventory.get("criticality_weights", {}).get(criticality, 1.0)
    exp_weight = inventory.get("exposure_weights", {}).get(exposure, 1.0)

    return crit_weight * exp_weight


def days_since(date_string):
    """Days elapsed since a date in Nessus's YYYY/MM/DD format."""
    if not date_string:
        return None
    try:
        published = datetime.strptime(date_string, "%Y/%m/%d").replace(
            tzinfo=timezone.utc
        )
    except (ValueError, TypeError):
        return None
    return (datetime.now(timezone.utc) - published).days


def score_finding(finding, inventory):
    """Calculate a risk score and attach the full working to the finding.

    Every intermediate value is recorded, not just the result. A score an
    analyst cannot interrogate is a score they will not trust, and in a
    ticketing pipeline an unexplained number is the fastest route to the whole
    system being ignored.
    """
    impact, impact_source = resolve_impact(finding)
    likelihood, likelihood_source = resolve_likelihood(finding)

    asset = resolve_asset(finding, inventory)
    multiplier = asset_multiplier(asset, inventory)

    # Impact is 0-10, likelihood is 0-1. Normalise impact so the weights mean
    # what they say.
    base = (IMPACT_WEIGHT * (impact / 10.0)) + (LIKELIHOOD_WEIGHT * likelihood)
    score = base * multiplier * 100

    # Confirmed exploitation sets a floor. Everything above this line is
    # estimation; KEV membership is observation, and should not be argued down
    # by a missing or low score elsewhere.
    floored = False
    if finding.get("kev") and score < KEV_FLOOR:
        score = KEV_FLOOR
        floored = True

    finding["risk_score"] = round(min(score, 100.0), 2)
    finding["score_components"] = {
        "impact": impact,
        "impact_source": impact_source,
        "likelihood": round(likelihood, 4),
        "likelihood_source": likelihood_source,
        "asset_multiplier": round(multiplier, 3),
        "kev_floor_applied": floored,
    }
    finding["asset"] = {
        "name": asset.get("name"),
        "criticality": asset.get("criticality"),
        "exposure": asset.get("exposure"),
        "owner": asset.get("owner"),
    }
    finding["patch_age_days"] = days_since(finding.get("patch_publication_date"))

    return finding


def severity_rank(findings):
    """Order findings the way a severity-sorted queue would.

    Ties within a severity band are broken by CVSS, which is what most tools
    do by default.
    """
    return sorted(
        findings,
        key=lambda f: (
            -f.get("severity", 0),
            -(f.get("cvss3_base_score") or f.get("cvss_base_score") or 0),
        ),
    )


def risk_rank(findings):
    """Order findings by the model's risk score."""
    return sorted(findings, key=lambda f: -f.get("risk_score", 0))


def deduplicate(findings):
    """Collapse repeated plugins to their highest-scoring instance.

    The same vulnerability appears across several scan runs. For comparing
    orderings, one row per distinct vulnerability per host is clearer than
    several identical rows.
    """
    best = {}
    for finding in findings:
        key = (finding.get("host_ip"), finding.get("plugin_id"))
        if key not in best or finding["risk_score"] > best[key]["risk_score"]:
            best[key] = finding
    return list(best.values())


def print_table(title, findings, limit=15):
    """Print a ranked list of findings."""
    print(f"\n{title}")
    print("-" * 94)
    print(f"{'#':>3}  {'Severity':<14} {'Risk':>6}  {'EPSS':>7}  "
          f"{'KEV':>4}  Finding")
    print("-" * 94)

    for position, finding in enumerate(findings[:limit], start=1):
        epss = finding.get("epss_live")
        epss_text = f"{epss:.4f}" if epss is not None else "    -  "
        kev_text = "yes" if finding.get("kev") else " - "
        name = finding.get("plugin_name", "")[:48]

        print(f"{position:>3}  {finding['severity_label']:<14} "
              f"{finding['risk_score']:>6.1f}  {epss_text:>7}  "
              f"{kev_text:>4}  {name}")


def report_movement(findings, limit=15):
    """Show which findings the model promotes and which it demotes.

    This is the point of the exercise. If the risk ranking and the severity
    ranking produce the same queue, the model has added nothing.
    """
    by_severity = severity_rank(findings)
    by_risk = risk_rank(findings)

    severity_positions = {
        (f["host_ip"], f["plugin_id"]): i
        for i, f in enumerate(by_severity, start=1)
    }

    moves = []
    for risk_position, finding in enumerate(by_risk, start=1):
        key = (finding["host_ip"], finding["plugin_id"])
        old = severity_positions[key]
        moves.append((old - risk_position, old, risk_position, finding))

    promoted = sorted(moves, key=lambda m: -m[0])[:limit]
    demoted = sorted(moves, key=lambda m: m[0])[:limit]

    print("\nPromoted by the risk model")
    print("-" * 94)
    print(f"{'Severity rank':>13} -> {'Risk rank':<10} {'Severity':<14} "
          f"{'EPSS':>7}  Finding")
    print("-" * 94)
    for gain, old, new, finding in promoted:
        if gain <= 0:
            continue
        epss = finding.get("epss_live")
        epss_text = f"{epss:.4f}" if epss is not None else "    -  "
        print(f"{old:>13} -> {new:<10} {finding['severity_label']:<14} "
              f"{epss_text:>7}  {finding['plugin_name'][:44]}")

    print("\nDemoted by the risk model")
    print("-" * 94)
    print(f"{'Severity rank':>13} -> {'Risk rank':<10} {'Severity':<14} "
          f"{'EPSS':>7}  Finding")
    print("-" * 94)
    for loss, old, new, finding in demoted:
        if loss >= 0:
            continue
        epss = finding.get("epss_live")
        epss_text = f"{epss:.4f}" if epss is not None else "    -  "
        print(f"{old:>13} -> {new:<10} {finding['severity_label']:<14} "
              f"{epss_text:>7}  {finding['plugin_name'][:44]}")


def report_sources(findings):
    """Report which evidence tier each finding's score rested on.

    A model that degrades through tiers is only defensible if you can say how
    often each tier was used. If most scores rest on the weakest tier, the
    ranking is mostly guesswork wearing a number.
    """
    total = len(findings)

    print("\nEvidence used")
    print("-" * 52)

    print("  Likelihood")
    counts = {}
    for finding in findings:
        source = finding["score_components"]["likelihood_source"]
        counts[source] = counts.get(source, 0) + 1
    for source, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {source:<22} {count:>5}  ({count / total * 100:5.1f}%)")

    print("  Impact")
    counts = {}
    for finding in findings:
        source = finding["score_components"]["impact_source"]
        counts[source] = counts.get(source, 0) + 1
    for source, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {source:<22} {count:>5}  ({count / total * 100:5.1f}%)")


def main():
    parser = argparse.ArgumentParser(
        description="Rank findings by risk rather than severity."
    )
    parser.add_argument("--input", default="enriched.json")
    parser.add_argument("--assets", default="assets.json")
    parser.add_argument("--output", default="scored.json")
    parser.add_argument("--limit", type=int, default=15,
                        help="Rows to show in each table")
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

    for finding in findings:
        score_finding(finding, inventory)

    output_path = Path(args.output).expanduser()
    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"Scored {len(findings)} findings -> {output_path}")

    # Informational findings are excluded from the comparison. They are not
    # remediation work, and including 298 of them would drown the signal.
    actionable = [f for f in findings if f.get("severity", 0) > 0]
    unique = deduplicate(actionable)

    print(f"{len(actionable)} actionable findings, "
          f"{len(unique)} distinct vulnerability-host pairs")

    report_sources(unique)
    print_table("Top findings by severity (how most tools rank)",
                severity_rank(unique), args.limit)
    print_table("Top findings by risk score (this model)",
                risk_rank(unique), args.limit)
    report_movement(unique, args.limit)

    return 0


if __name__ == "__main__":
    sys.exit(main())
