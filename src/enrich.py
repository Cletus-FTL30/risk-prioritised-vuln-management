#!/usr/bin/env python3
"""
enrich.py

Adds live exploit intelligence to the normalised finding dataset.

Two public sources, both free and unauthenticated:

  FIRST EPSS   probability that a CVE will be exploited in the next 30 days
  CISA KEV     catalogue of vulnerabilities confirmed as actively exploited

These answer different questions. EPSS is a prediction, continuous and updated
daily. KEV is an observation, binary and authoritative: a vulnerability is on
the list because exploitation has been seen in the wild. A high EPSS score
means "likely"; KEV membership means "already happening".

Nessus carries its own cached EPSS values, but only on some findings and only
as of whenever its plugin feed was built. Querying the source directly gives
current values and covers findings the scanner left blank.

Where a finding references several CVEs, the highest EPSS score is used, and
KEV membership applies if any of its CVEs is listed. A finding is as dangerous
as its worst component.

Usage:
    python3 enrich.py --input findings.json --output enriched.json
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")

# The EPSS cve parameter accepts up to 2000 characters including commas, and
# returns 100 records by default. Batching at 80 keeps both within bounds.
BATCH_SIZE = 80

# Courtesy delay between requests to a free public API.
REQUEST_DELAY = 0.5


def fetch_json(url, timeout=30):
    """GET a URL and parse the response as JSON."""
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "vuln-pipeline/1.0 (portfolio project)"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def collect_cves(findings):
    """Gather every distinct CVE referenced across the dataset."""
    cves = set()
    for finding in findings:
        cves.update(finding.get("cves") or [])
    return sorted(cves)


def fetch_epss(cves):
    """Look up EPSS scores for a list of CVEs, in batches.

    Returns a dict of cve -> {"epss": float, "percentile": float}. CVEs absent
    from the EPSS dataset are simply missing from the result, which is a
    meaningful outcome rather than an error: EPSS only covers published CVEs
    that have been through its model.
    """
    scores = {}
    batches = [cves[i:i + BATCH_SIZE] for i in range(0, len(cves), BATCH_SIZE)]

    for index, batch in enumerate(batches, start=1):
        url = f"{EPSS_API}?cve={','.join(batch)}&limit={BATCH_SIZE}"
        print(f"  EPSS batch {index}/{len(batches)} ({len(batch)} CVEs)",
              end="", flush=True)

        try:
            payload = fetch_json(url)
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
            print(f"  failed: {exc}")
            continue

        for record in payload.get("data", []):
            scores[record["cve"]] = {
                "epss": float(record["epss"]),
                "percentile": float(record["percentile"]),
            }

        print(f"  -> {len(payload.get('data', []))} scored")
        time.sleep(REQUEST_DELAY)

    return scores


def fetch_kev():
    """Download the CISA Known Exploited Vulnerabilities catalogue.

    Returns a dict of cve -> catalogue entry.
    """
    print("  downloading CISA KEV catalogue", end="", flush=True)

    try:
        payload = fetch_json(KEV_FEED, timeout=60)
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        print(f"  failed: {exc}")
        return {}

    entries = {
        item["cveID"]: {
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "known_ransomware": item.get("knownRansomwareCampaignUse"),
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "required_action": item.get("requiredAction"),
        }
        for item in payload.get("vulnerabilities", [])
    }

    print(f"  -> {len(entries)} entries")
    return entries


def enrich_finding(finding, epss_scores, kev_entries):
    """Attach EPSS and KEV data to a single finding.

    A finding may reference many CVEs. The worst case governs: highest EPSS,
    and KEV membership if any single CVE is listed.
    """
    cves = finding.get("cves") or []

    # EPSS: take the highest score among this finding's CVEs.
    scored = [(cve, epss_scores[cve]) for cve in cves if cve in epss_scores]
    if scored:
        worst_cve, worst = max(scored, key=lambda pair: pair[1]["epss"])
        finding["epss_live"] = worst["epss"]
        finding["epss_percentile"] = worst["percentile"]
        finding["epss_source_cve"] = worst_cve
    else:
        finding["epss_live"] = None
        finding["epss_percentile"] = None
        finding["epss_source_cve"] = None

    # KEV: membership is binary, but record which CVEs triggered it.
    listed = [cve for cve in cves if cve in kev_entries]
    finding["kev"] = bool(listed)
    finding["kev_cves"] = listed

    if listed:
        entry = kev_entries[listed[0]]
        finding["kev_date_added"] = entry["date_added"]
        finding["kev_due_date"] = entry["due_date"]
        finding["kev_ransomware"] = entry["known_ransomware"]
    else:
        finding["kev_date_added"] = None
        finding["kev_due_date"] = None
        finding["kev_ransomware"] = None

    return finding


def report(findings):
    """Summarise what enrichment added, and what it revealed."""
    total = len(findings)
    with_cve = [f for f in findings if f.get("cves")]
    with_epss = [f for f in findings if f.get("epss_live") is not None]
    kev = [f for f in findings if f.get("kev")]

    print("\nEnrichment results")
    print("-" * 52)
    print(f"  Total findings              {total}")
    print(f"  With at least one CVE       {len(with_cve)}")
    print(f"  Scored by EPSS              {len(with_epss)}")
    print(f"  On the CISA KEV catalogue   {len(kev)}")

    # Findings Nessus left unscored that the live API could score. This is the
    # gap between a cached plugin feed and the current source.
    recovered = [f for f in findings
                 if f.get("epss_live") is not None and not f.get("epss_score")]
    print(f"  EPSS recovered from source  {len(recovered)}")

    if kev:
        print("\nActively exploited (CISA KEV)")
        print("-" * 52)
        seen = set()
        for finding in sorted(kev, key=lambda f: -(f.get("epss_live") or 0)):
            name = finding["plugin_name"][:44]
            if name in seen:
                continue
            seen.add(name)
            epss = finding.get("epss_live")
            epss_text = f"{epss:.4f}" if epss is not None else "  n/a "
            ransom = " [ransomware]" if finding.get("kev_ransomware") == "Known" else ""
            print(f"  {finding['severity_label']:<14} EPSS {epss_text}  "
                  f"{name}{ransom}")

    # Where severity and exploitation likelihood disagree. This is the case
    # the whole project exists to address.
    mismatches = [
        f for f in findings
        if (f.get("epss_live") or 0) > 0.5 and f["severity"] <= 2
    ]
    if mismatches:
        print("\nMedium or lower, but high exploitation likelihood")
        print("-" * 52)
        seen = set()
        for finding in sorted(mismatches, key=lambda f: -(f["epss_live"] or 0)):
            name = finding["plugin_name"][:44]
            if name in seen:
                continue
            seen.add(name)
            print(f"  {finding['severity_label']:<14} "
                  f"EPSS {finding['epss_live']:.4f}  {name}")

    # And the reverse: rated Critical, but unlikely to be exploited.
    overrated = [
        f for f in findings
        if f["severity"] == 4 and f.get("epss_live") is not None
        and f["epss_live"] < 0.01
    ]
    if overrated:
        print("\nCritical, but low exploitation likelihood")
        print("-" * 52)
        seen = set()
        for finding in sorted(overrated, key=lambda f: f["epss_live"]):
            name = finding["plugin_name"][:44]
            if name in seen:
                continue
            seen.add(name)
            print(f"  {finding['severity_label']:<14} "
                  f"EPSS {finding['epss_live']:.4f}  {name}")


def main():
    parser = argparse.ArgumentParser(
        description="Enrich findings with EPSS scores and CISA KEV membership."
    )
    parser.add_argument("--input", default="findings.json")
    parser.add_argument("--output", default="enriched.json")
    args = parser.parse_args()

    input_path = Path(args.input).expanduser()
    if not input_path.exists():
        print(f"Input not found: {input_path}", file=sys.stderr)
        return 1

    with open(input_path) as f:
        findings = json.load(f)

    cves = collect_cves(findings)
    print(f"Loaded {len(findings)} findings referencing "
          f"{len(cves)} distinct CVEs\n")

    if not cves:
        print("No CVEs to enrich.", file=sys.stderr)
        return 1

    epss_scores = fetch_epss(cves)
    kev_entries = fetch_kev()

    if not epss_scores and not kev_entries:
        print("\nBoth sources failed. Check network connectivity.",
              file=sys.stderr)
        return 1

    for finding in findings:
        enrich_finding(finding, epss_scores, kev_entries)

    output_path = Path(args.output).expanduser()
    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"\nWrote {len(findings)} enriched findings to {output_path}")
    report(findings)

    return 0


if __name__ == "__main__":
    sys.exit(main())
