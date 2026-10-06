#!/usr/bin/env python3
"""
parse_nessus.py

Reads raw Nessus scan exports and produces a normalised finding dataset.

Nessus spreads what you need for risk scoring across three sources, and they
are not equally complete:

  vulnerabilities[]          every finding, but only id/name/severity/count
  prioritization.plugins[]   rich detail (CVEs, CVSS, VPR drivers) for a
                             small subset of findings only
  plugins/<id>.json          per-plugin detail captured separately

The vulnerabilities array is the source of truth for what was found. The other
two are enrichment layered on top. Getting this the wrong way round silently
drops most of the dataset, because prioritization is populated for only a
handful of plugins.

One record is emitted per (run, host, plugin) with a consistent shape, so later
stages never have to know how Nessus structures its output.

Usage:
    python3 parse_nessus.py --input ~/nessus-data --output findings.json
"""

import argparse
import json
import sys
from pathlib import Path


SEVERITY_LABELS = {
    0: "Informational",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}


def load_json(path):
    """Read a JSON file, returning None rather than raising on bad input.

    Captured files may be API error responses rather than data, so a failed
    load is an expected condition, not an exception.
    """
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def to_float(value):
    """Convert a Nessus score to float. Scores arrive as strings or None."""
    if value in (None, "", "N/A"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def as_list(value):
    """Normalise a value that may be absent, single, or already a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def extract_refs(plugin_attributes, ref_name):
    """Pull a named reference list (cve, usn, cwe) out of ref_information.

    Nessus nests these as:
        ref_information.ref[] -> {name: "cve", values: {value: [...]}}
    """
    ref_info = plugin_attributes.get("ref_information") or {}

    for ref in ref_info.get("ref") or []:
        if ref.get("name") == ref_name:
            return as_list((ref.get("values") or {}).get("value"))

    return []


def flatten_plugin_file(plugin_dir, plugin_id):
    """Read a standalone plugin record and flatten its attribute list.

    Plugin files store attributes as a list of {attribute_name, attribute_value}
    pairs. Names can repeat (a plugin with several CVEs), so repeated names
    collect into a list rather than overwriting.
    """
    data = load_json(Path(plugin_dir) / f"{plugin_id}.json")
    if not data or "attributes" not in data:
        return {}

    flat = {}
    for attr in data["attributes"]:
        name = attr.get("attribute_name")
        if name is None:
            continue
        value = attr.get("attribute_value")

        if name in flat:
            existing = flat[name]
            flat[name] = existing + [value] if isinstance(existing, list) \
                         else [existing, value]
        else:
            flat[name] = value

    return flat


def build_prioritization_index(scan_data):
    """Map plugin_id to its rich attributes, where Nessus provided them.

    This block covers only a fraction of findings, so every lookup against it
    must tolerate a miss.
    """
    plugins = (scan_data.get("prioritization") or {}).get("plugins", [])
    return {p["pluginid"]: p for p in plugins if p.get("pluginid")}


def build_finding(run, host, vuln, prio, plugin_file):
    """Assemble one normalised finding from all three sources.

    Precedence is: scan-level prioritization data, then the separately captured
    plugin file, then whatever the vulnerabilities array itself carries.
    """
    attrs = (prio or {}).get("pluginattributes") or {}
    risk = attrs.get("risk_information") or {}
    vuln_info = attrs.get("vuln_information") or {}

    cves = extract_refs(attrs, "cve") or as_list(plugin_file.get("cve"))
    severity = vuln.get("severity", 0)
    plugin_id = vuln.get("plugin_id")

    return {
        # Identity
        "finding_id": f"{run['run_id']}:{host['ip']}:{plugin_id}",
        "run_id": run["run_id"],
        "scan_name": run["scan_name"],
        "authenticated": run["authenticated"],
        "scan_start": run["scan_start"],

        # Asset
        "host_ip": host["ip"],
        "hostname": host["hostname"],

        # Vulnerability
        "plugin_id": plugin_id,
        "plugin_name": vuln.get("plugin_name"),
        "plugin_family": vuln.get("plugin_family"),
        "severity": severity,
        "severity_label": SEVERITY_LABELS.get(severity, "Unknown"),
        "instance_count": vuln.get("count", 1),
        "cves": cves,
        "cve_count": len(cves),
        "usns": extract_refs(attrs, "usn"),
        "cwes": extract_refs(attrs, "cwe"),

        # Scoring inputs. Any of these may be absent. A missing signal is left
        # as null rather than defaulted to zero, because "no data" and "scored
        # zero" mean very different things when ranking.
        "cvss_base_score": to_float(risk.get("cvss_base_score"))
                           or to_float(plugin_file.get("cvss_base_score")),
        "cvss3_base_score": to_float(risk.get("cvss3_base_score"))
                            or to_float(plugin_file.get("cvss3_base_score")),
        "cvss_temporal_score": to_float(risk.get("cvss_temporal_score")),
        "cvss_vector": risk.get("cvss_vector"),
        "risk_factor": risk.get("risk_factor") or plugin_file.get("risk_factor"),
        "vpr_score": to_float(attrs.get("vpr_score"))
                     or to_float(vuln.get("vpr_score"))
                     or to_float(plugin_file.get("vpr_score")),
        "epss_score": to_float(vuln.get("epss_score"))
                      or to_float(plugin_file.get("epss_score")),

        # Threat context. Tenable's VPR drivers, present on many findings that
        # carry no EPSS score at all.
        "exploit_available": plugin_file.get("exploit_available"),
        "exploitability_ease": plugin_file.get("exploitability_ease"),
        "exploit_code_maturity": attrs.get("exploit_code_maturity"),
        "exploited_by_malware": attrs.get("exploited_by_malware"),
        "threat_recency": attrs.get("threat_recency"),
        "threat_intensity": attrs.get("threat_intensity_last_28"),
        "age_of_vuln": attrs.get("age_of_vuln"),
        "product_coverage": attrs.get("product_coverage"),

        # Remediation
        "patch_publication_date": vuln_info.get("patch_publication_date")
                                  or plugin_file.get("patch_publication_date"),
        "vuln_publication_date": vuln_info.get("vuln_publication_date")
                                 or plugin_file.get("vuln_publication_date"),
        "solution": attrs.get("solution") or plugin_file.get("solution"),
        "synopsis": attrs.get("synopsis") or plugin_file.get("synopsis"),
    }


def parse_scan(scan_path, plugin_dir):
    """Turn one scan file into a list of normalised findings."""
    data = load_json(scan_path)
    if not data:
        print(f"  unreadable, skipped: {scan_path.name}", file=sys.stderr)
        return []

    info = data.get("info") or {}
    hosts = data.get("hosts") or []

    # A scan is authenticated if any host reports a successful credential
    # check. This is the Auth Pass/Fail column, as data.
    #
    # The field arrives as the STRING "false", not a boolean. Any non-empty
    # string is truthy in Python, so a plain truth test marks every scan as
    # authenticated, including the unauthenticated baselines, silently.
    run = {
        # The file stem, not the scan id: one scan can have several runs and
        # they must not collide in the output.
        "run_id": scan_path.stem,
        "scan_name": info.get("name"),
        "authenticated": any(
            str(h.get("credential", "")).lower() == "true" for h in hosts
        ),
        "scan_start": info.get("scan_start"),
    }

    # These scans each target a single host. Where a scan covers several, the
    # vulnerabilities array does not say which host each finding belongs to,
    # so attribution would need the per-host endpoint instead.
    if hosts:
        host = {
            "ip": hosts[0].get("hostname"),
            "hostname": hosts[0].get("hostname"),
        }
    else:
        host = {"ip": None, "hostname": None}

    prio_index = build_prioritization_index(data)

    findings = []
    for vuln in data.get("vulnerabilities", []):
        plugin_id = vuln.get("plugin_id")
        findings.append(
            build_finding(
                run,
                host,
                vuln,
                prio_index.get(plugin_id),
                flatten_plugin_file(plugin_dir, plugin_id),
            )
        )

    return findings


def report_coverage(findings):
    """Print how complete the dataset is, field by field.

    Stage 4's model depends on these signals, so knowing which are sparse is a
    design input, not a diagnostic afterthought. A signal present on 10% of
    findings cannot be the backbone of a ranking.
    """
    total = len(findings)
    if total == 0:
        return

    fields = [
        "cves", "cvss_base_score", "cvss3_base_score", "vpr_score",
        "epss_score", "exploit_available", "exploit_code_maturity",
        "patch_publication_date", "solution",
    ]

    print("\nSignal coverage")
    print("-" * 48)
    for field in fields:
        present = sum(1 for f in findings if f.get(field))
        print(f"  {field:<26} {present:>5} / {total}  ({present / total * 100:5.1f}%)")

    print("\nSeverity distribution")
    print("-" * 48)
    for level in (4, 3, 2, 1, 0):
        count = sum(1 for f in findings if f["severity"] == level)
        if count:
            print(f"  {SEVERITY_LABELS[level]:<26} {count:>5}")


def main():
    parser = argparse.ArgumentParser(
        description="Normalise Nessus scan exports into a single finding dataset."
    )
    parser.add_argument("--input", default="~/nessus-data",
                        help="Directory holding scan-*.json and plugins/")
    parser.add_argument("--output", default="findings.json",
                        help="Where to write the normalised dataset")
    args = parser.parse_args()

    input_dir = Path(args.input).expanduser()
    plugin_dir = input_dir / "plugins"

    scan_files = sorted(input_dir.glob("scan-*.json"))
    if not scan_files:
        print(f"No scan files found in {input_dir}", file=sys.stderr)
        return 1

    print(f"Reading {len(scan_files)} scan files from {input_dir}\n")

    all_findings = []
    for scan_path in scan_files:
        findings = parse_scan(scan_path, plugin_dir)
        all_findings.extend(findings)

        if findings:
            auth = "authenticated" if findings[0]["authenticated"] \
                   else "unauthenticated"
            print(f"  {scan_path.stem:<20} {findings[0]['scan_name']}")
            print(f"  {'':<20} {len(findings)} findings, {auth}")

    output_path = Path(args.output).expanduser()
    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2)

    print(f"\nWrote {len(all_findings)} findings to {output_path}")
    report_coverage(all_findings)

    return 0


if __name__ == "__main__":
    sys.exit(main())
