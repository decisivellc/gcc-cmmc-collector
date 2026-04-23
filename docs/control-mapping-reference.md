# Control Mapping Reference

Which collected evidence drives which NIST 800-171 r2 control. The mapper implementation lives in `mappers/nist_800_171.py` — one `_map_<id>()` helper per control. Control cards are rendered in `templates/report.html` via a single loop (no per-control partial template by design — a dedicated `evidence_card.html` would add ceremony without payoff for this scope).

| Control | Title | Primary evidence | Compliant when |
|---|---|---|---|
| AC-1 | Access Control Policy | Conditional-access policies exist | MFA-requiring CA policy enabled **and** written policy documented (manual) |
| AC-2 | Account Management | `users[]`, `mfaStatus`, `lastActiveInDays` | 100% MFA, no accounts inactive >30 days |
| AC-3 | Access Enforcement | Conditional-access policies | ≥1 enabled CA policy |
| AC-6 | Least Privilege | `assignedRoles[]` per user | 1-2 Global Admins; privileged users ≤ 30% of active users |
| IA-2 | Identification and Authentication (Users) | MFA registration + MFA CA policy | All active users MFA-registered + MFA CA policy enabled |
| IA-4 | Identifier Management | Directory user inventory | Always COMPLIANT (Entra enforces UPN uniqueness) |
| IA-5 | Authenticator Management | `passwordPolicy` | Minimum length ≥ 12, complexity required |
| AU-2 | Audit Events | `auditLogs.sample` | Directory audit readable with ≥1 sample event |
| AU-3 | Audit Record Content | `auditLogs.sample[0]` fields | `initiatedBy`, `activityDisplayName`, `activityDateTime` all present |
| AU-6 | Audit Review & Analysis | n/a (manual) | Always PARTIAL — documented review cadence required |
| AU-12 | Audit Generation | Azure AD + Exchange audit | Both directory and Exchange audit streams readable |
| SC-7 | Boundary Protection | CA policies with `block` / `compliantDevice` grant controls | ≥1 such policy enabled (plus manual network validation) |
| SI-2 | Flaw Remediation | `intune.devices[]` compliance + OS version | All devices compliant **and** on macOS ≥ 14.3 |
| SI-3 | Malicious Code Protection | Defender AV health + active threats | All agents healthy, zero active alerts |
| SI-4 | System Monitoring | Microsoft Secure Score | Score ≥ 70% of max |
| IR-1 | Incident Response Policy | n/a | Always NOT_ADDRESSED — requires written IR plan |
| IR-4 | Incident Handling | Defender resolved threats (as tooling proxy) | Always PARTIAL — runbooks required |
| AT-1 | Security Awareness Training | n/a | Always NOT_ADDRESSED — LMS completion needed |

## Status semantics

- **COMPLIANT** — automated signals confirm the control objective is met.
- **PARTIAL** — automated signals show most of the control is in place, or a manual element (written policy, documented process) is still required.
- **NOT_ADDRESSED** — no automated evidence found, or no automated signal exists for this control.

The HTML dashboard colors each status green / orange / red; the raw `evidence.json` and `remediation-backlog.json` use the string tokens above (no emoji) so they are easy to grep and feed into downstream tooling.

## Remediation buckets

Each control mapper tags its remediation with a bucket used by `generate_remediation_backlog()`:

- `quick_win` — less than 1 day of effort.
- `medium` — 1-3 days.
- `heavy_lift` — more than 1 week (typically requires new policies, training programs, or tabletop exercises).

The dashboard and `remediation-backlog.json` sort outstanding work by these buckets so a DIB contractor can knock out the quick wins before a C3PAO assessment kick-off.
