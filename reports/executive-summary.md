# Vulnerability Assessment: Executive Summary

---

## The position

An assessment of 2 systems identified **292 distinct security weaknesses**.

Of these, **17 require action within the next two weeks**. The remainder can be scheduled into normal maintenance.

**4 are confirmed as being actively exploited by attackers today**, according to the US Cybersecurity and Infrastructure Security Agency. These are not theoretical weaknesses. Working attacks exist and are in use.

## What this means

Security tools rate weaknesses by how much damage they could cause if exploited. That is only half the question. The other half is whether anyone is actually exploiting them.

This assessment combines both. The result is that of 139 findings the scanner rated as Critical or High, **86 present little practical risk** and can safely be scheduled rather than rushed.

That matters because a remediation list nobody can finish gets ignored. A list of 17 items gets done.

## How long this has been true

For the findings where a vendor fix exists, the median time since that fix was published is **16 years**.

These are not newly discovered problems. They are known problems with known solutions that have not been applied. The exposure is the gap between the two.

## Recommended action

1. **This fortnight.** Remediate the 17 findings identified as urgent. These are assigned and dated.

2. **Address the root cause.** 91% of all findings sit on a single system (*metasploitable*) running software that is no longer supported by its vendor and receives no security updates. Patching its findings individually is not possible. The system needs rebuilding on a supported platform. Doing so resolves the majority of this report in one action.

3. **Schedule the remainder** into routine maintenance windows according to the assigned deadlines.

## Remediation schedule

| Priority | Deadline | Findings |
|---|---|---|
| Critical | 7 days | 4 |
| High | 14 days | 13 |
| Moderate | 30 days | 49 |
| Low | 90 days | 169 |
| Planning | 180 days | 57 |

---

*Every finding in this summary is tracked individually with an assigned owner and deadline. Technical detail is in the accompanying findings report.*
