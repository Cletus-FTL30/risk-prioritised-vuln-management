#!/usr/bin/env python3
"""
push_servicenow.py

Creates remediation records in ServiceNow from scored findings.

A ranked list is not work. Someone has to own each item and have a date by
which it is due. This script turns the output of the scoring model into
vulnerable item records, each attached to a configuration item, assigned to a
team, and carrying a due date derived from its risk score.

Three decisions are made here, and they are the substance of this stage:

  routing   which team fixes it, inferred from what kind of finding it is
  SLA       how long they have, derived from risk score not severity label
  linkage   which asset it belongs to, matched against the CMDB

Usage:
    export SN_INSTANCE=dev123456
    export SN_USER=vuln_pipeline
    export SN_PASS=...

    python3 push_servicenow.py --input scored-v2.json --assets assets.json
"""

import argparse
import base64
import csv
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


TABLE = "u_vulnerable_item"
CI_TABLE = "cmdb_ci_server"
GROUP_TABLE = "sys_user_group"


# Remediation deadlines, driven by risk score rather than severity.
#
# The KEV floor in the scoring model is 80, so every confirmed-exploited
# finding lands in the top band automatically. That is the intent: a
# vulnerability known to be exploited in the wild gets the shortest clock
# regardless of what its CVSS score says.
SLA_BANDS = [
    (80, 7,   "1 - Critical"),
    (60, 14,  "2 - High"),
    (40, 30,  "3 - Moderate"),
    (20, 90,  "4 - Low"),
    (0,  180, "5 - Planning"),
]


def resolve_sla(risk_score):
    """Return (days, priority_label) for a risk score."""
    for threshold, days, priority in SLA_BANDS:
        if risk_score >= threshold:
            return days, priority
    return 180, "5 - Planning"


# Routing rules, evaluated in order. The first match wins.
#
# Stage 2 established that findings are not uniformly patch work: a missing
# package update, a weak password and an active backdoor need three different
# responses from three different teams. Routing everything to one queue on
# severity alone is how remediation programmes stall.
#
# An earlier version of these rules matched keywords in the plugin name only,
# which misclassified an "openssl vulnerabilities (USN-...)" package update as
# configuration work because its name contains "ssl". The presence of a vendor
# advisory is checked first for that reason: whether a fix has been published
# is a fact about the finding, while a keyword in its title is a guess.
ROUTING_RULES = [
    # Suspected compromise. Not a patch, an incident. This overrides
    # everything else, including the presence of an advisory.
    ("Security Operations", lambda f: any(
        term in f["plugin_name"].lower()
        for term in ("backdoor", "trojan", "malware", "compromise")
    )),

    # A published vendor fix means this is patch work, whatever the affected
    # component is called.
    ("Platform Engineering", lambda f: bool(f.get("usns"))
                                       or bool(f.get("patch_publication_date"))),

    # No patch available, so someone has to change a setting, a credential or
    # a protocol policy.
    ("Security Operations", lambda f: any(
        term in f["plugin_name"].lower()
        for term in ("password", "default account", "anonymous", "weak",
                     "world readable", "unencrypted", "cleartext",
                     "ssl", "tls", "cipher", "certificate")
    )),

    # Application and middleware layer.
    ("Application Support", lambda f: (
        f.get("plugin_family") in ("Web Servers", "Databases", "CGI abuses")
        or any(term in f["plugin_name"].lower()
               for term in ("tomcat", "apache", "mysql", "postgres", "php"))
    )),

    # Everything else: operating system and package patching.
    ("Platform Engineering", lambda f: True),
]


def route(finding):
    """Decide which team owns a finding."""
    for group, matches in ROUTING_RULES:
        if matches(finding):
            return group
    return "Platform Engineering"


class ServiceNow:
    """Minimal REST client for the ServiceNow Table API."""

    def __init__(self, instance, user, password):
        self.base = f"https://{instance}.service-now.com/api/now/table"
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self._group_cache = {}
        self._ci_cache = {}

    def _request(self, method, url, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            url, data=data, headers=self.headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read().decode()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:300]
            raise RuntimeError(f"{method} {url} -> {exc.code}: {detail}")

    def find_one(self, table, query):
        """Return the first record matching an encoded query, or None."""
        url = f"{self.base}/{table}?sysparm_query={query}&sysparm_limit=1"
        records = self._request("GET", url).get("result", [])
        return records[0] if records else None

    def create(self, table, payload):
        return self._request("POST", f"{self.base}/{table}", payload)

    def update(self, table, sys_id, payload):
        return self._request("PATCH", f"{self.base}/{table}/{sys_id}", payload)

    def group_id(self, name):
        """Look up an assignment group by name, with caching.

        Resolved by name rather than hardcoded sys_id. Hardcoded identifiers
        are the usual reason an integration breaks the moment it is moved to
        another instance.
        """
        if name not in self._group_cache:
            record = self.find_one(GROUP_TABLE, f"name={name}")
            self._group_cache[name] = record["sys_id"] if record else None
            if record is None:
                print(f"  warning: assignment group not found: {name}",
                      file=sys.stderr)
        return self._group_cache[name]

    def ci_id(self, ci_name, ip_address):
        """Look up a configuration item, setting its IP if absent.

        The CMDB record is the join between a vulnerability and a business
        asset. Without it a finding is just a row in a list.
        """
        if ci_name in self._ci_cache:
            return self._ci_cache[ci_name]

        record = self.find_one(CI_TABLE, f"name={ci_name}")
        if record is None:
            print(f"  warning: CI not found: {ci_name}", file=sys.stderr)
            self._ci_cache[ci_name] = None
            return None

        # Populate the IP if the record does not carry one. The pipeline
        # maintains the field it depends on rather than requiring it to be
        # filled in by hand.
        if ip_address and not record.get("ip_address"):
            self.update(CI_TABLE, record["sys_id"], {"ip_address": ip_address})
            print(f"  set IP on {ci_name}: {ip_address}")

        self._ci_cache[ci_name] = record["sys_id"]
        return record["sys_id"]


def deduplicate(findings):
    """One record per vulnerability-host pair, keeping the highest score."""
    best = {}
    for finding in findings:
        key = (finding.get("host_ip"), finding.get("plugin_id"))
        if key not in best or finding["risk_score"] > best[key]["risk_score"]:
            best[key] = finding
    return list(best.values())


def build_payload(finding, snow, asset_names):
    """Turn a scored finding into a ServiceNow record payload."""
    days, priority = resolve_sla(finding["risk_score"])
    due = datetime.now(timezone.utc) + timedelta(days=days)

    group_name = route(finding)
    host_ip = finding.get("host_ip")
    ci_name = asset_names.get(host_ip)

    payload = {
        "u_finding_id": finding["finding_id"],
        "u_plugin_id": str(finding.get("plugin_id", "")),
        "u_plugin_name": (finding.get("plugin_name") or "")[:1000],
        "u_severity": finding.get("severity_label", ""),
        "u_risk_score": str(finding["risk_score"]),
        "u_host_ip": host_ip or "",
        "u_cves": ", ".join(finding.get("cves") or [])[:1000],
        "u_kev": "true" if finding.get("kev") else "false",
        "u_solution": (finding.get("solution") or "")[:4000],
        "u_due_date": due.strftime("%Y-%m-%d %H:%M:%S"),
    }

    epss = finding.get("epss_live")
    if epss is not None:
        payload["u_epss_score"] = str(epss)

    group_id = snow.group_id(group_name)
    if group_id:
        payload["u_assignment_group"] = group_id

    if ci_name:
        ci_id = snow.ci_id(ci_name, host_ip)
        if ci_id:
            payload["u_ci"] = ci_id

    return payload, group_name, days, priority



CSV_COLUMNS = [
    "u_finding_id", "u_plugin_id", "u_plugin_name", "u_severity",
    "u_risk_score", "u_epss_score", "u_kev", "u_cves", "u_host_ip",
    "u_ci", "u_assignment_group", "u_due_date", "u_solution",
]


def write_csv(path, findings, asset_names):
    """Write records to CSV for loading through ServiceNow Import Sets.

    Produced without an authenticated session, so the routing and SLA logic
    can be exercised and reviewed independently of API access. Reference
    fields carry display names rather than sys_ids; the import transform map
    resolves them on the way in.
    """
    rows = []
    for finding in findings:
        days, _ = resolve_sla(finding["risk_score"])
        due = datetime.now(timezone.utc) + timedelta(days=days)
        host_ip = finding.get("host_ip")

        rows.append({
            "u_finding_id": finding["finding_id"],
            "u_plugin_id": str(finding.get("plugin_id", "")),
            "u_plugin_name": (finding.get("plugin_name") or "")[:1000],
            "u_severity": finding.get("severity_label", ""),
            "u_risk_score": finding["risk_score"],
            "u_epss_score": finding.get("epss_live") or "",
            "u_kev": "true" if finding.get("kev") else "false",
            "u_cves": ", ".join(finding.get("cves") or [])[:1000],
            "u_host_ip": host_ip or "",
            "u_ci": asset_names.get(host_ip, ""),
            "u_assignment_group": route(finding),
            "u_due_date": due.strftime("%Y-%m-%d %H:%M:%S"),
            "u_solution": (finding.get("solution") or "")[:4000],
        })

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Push scored findings into ServiceNow as vulnerable items."
    )
    parser.add_argument("--input", default="scored-v2.json")
    parser.add_argument("--assets", default="assets.json")
    parser.add_argument("--limit", type=int, default=0,
                        help="Maximum records to create (0 = no limit)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be created without creating it")
    parser.add_argument("--csv",
                        help="Write records to this CSV instead of calling the API")
    args = parser.parse_args()

    instance = os.environ.get("SN_INSTANCE")
    user = os.environ.get("SN_USER")
    password = os.environ.get("SN_PASS")

    needs_api = not args.dry_run and not args.csv
    if needs_api and not all([instance, user, password]):
        print("Set SN_INSTANCE, SN_USER and SN_PASS first.", file=sys.stderr)
        return 1

    with open(Path(args.input).expanduser()) as f:
        findings = json.load(f)
    with open(Path(args.assets).expanduser()) as f:
        inventory = json.load(f)

    # Map host IP to the CI name it should link to.
    asset_names = {
        ip: asset.get("name")
        for ip, asset in inventory.get("assets", {}).items()
    }

    # Informational findings are not remediation work and do not get tickets.
    actionable = [f for f in findings if f.get("severity", 0) > 0]
    unique = sorted(deduplicate(actionable),
                    key=lambda f: -f["risk_score"])

    if args.limit:
        unique = unique[:args.limit]

    print(f"{len(findings)} findings loaded, "
          f"{len(unique)} to create\n")

    if args.csv:
        count = write_csv(Path(args.csv).expanduser(), unique, asset_names)
        print(f"Wrote {count} records to {args.csv}")

        by_group = {}
        bands = {}
        for finding in unique:
            by_group[route(finding)] = by_group.get(route(finding), 0) + 1
            days, priority = resolve_sla(finding["risk_score"])
            bands[(days, priority)] = bands.get((days, priority), 0) + 1

        print("\nAssigned to")
        print("-" * 46)
        for group, count in sorted(by_group.items(), key=lambda kv: -kv[1]):
            print(f"  {group:<24} {count:>5}")

        print("\nRemediation deadlines")
        print("-" * 46)
        for (days, priority), count in sorted(bands.items()):
            print(f"  {priority:<16} {days:>3} days   {count:>5}")

        return 0

    snow = None if args.dry_run else ServiceNow(instance, user, password)

    created = skipped = failed = 0
    by_group = {}

    for finding in unique:
        if args.dry_run:
            days, priority = resolve_sla(finding["risk_score"])
            group_name = route(finding)
            by_group[group_name] = by_group.get(group_name, 0) + 1
            print(f"  [{finding['risk_score']:>5.1f}] {days:>3}d  "
                  f"{group_name:<22} {finding['plugin_name'][:44]}")
            created += 1
            continue

        # Idempotent: a finding already present is left alone rather than
        # duplicated. Re-running the pipeline is a normal thing to do.
        existing = snow.find_one(
            TABLE, f"u_finding_id={finding['finding_id']}"
        )
        if existing:
            skipped += 1
            continue

        try:
            payload, group_name, days, _ = build_payload(
                finding, snow, asset_names
            )
            snow.create(TABLE, payload)
            created += 1
            by_group[group_name] = by_group.get(group_name, 0) + 1

            if created % 25 == 0:
                print(f"  {created} created...")
        except RuntimeError as exc:
            print(f"  failed: {finding['plugin_name'][:40]} -> {exc}",
                  file=sys.stderr)
            failed += 1

    print(f"\nCreated {created}, skipped {skipped} (already present), "
          f"failed {failed}")

    if by_group:
        print("\nAssigned to")
        print("-" * 46)
        for group, count in sorted(by_group.items(), key=lambda kv: -kv[1]):
            print(f"  {group:<24} {count:>5}")

    print("\nRemediation deadlines")
    print("-" * 46)
    bands = {}
    for finding in unique:
        days, priority = resolve_sla(finding["risk_score"])
        bands[(days, priority)] = bands.get((days, priority), 0) + 1
    for (days, priority), count in sorted(bands.items()):
        print(f"  {priority:<16} {days:>3} days   {count:>5}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
