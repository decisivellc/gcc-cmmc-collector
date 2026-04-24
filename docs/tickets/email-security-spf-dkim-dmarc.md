# Email security collector — SPF / DKIM / DMARC DNS checks

## Problem

SC-8 (Transmission Confidentiality and Integrity) and SC-12 (Cryptographic Key Establishment) for email depend on SPF, DKIM, and DMARC being correctly published in DNS. Today the tool has no visibility into any of this. It's a gap that's trivial to close — pure DNS lookups against the tenant's primary domain, no new Graph permissions.

## Proposed shape

- New collector `collectors/email_security.py`.
- Config: `collectors.email_security.domains` (list). Auto-populate from `/domains` Graph endpoint if empty.
- For each domain: DNS query for `_dmarc.<domain>` (DMARC TXT), `<selector>._domainkey.<domain>` (DKIM — try Microsoft's default selectors `selector1`, `selector2`), top-level TXT lookup for SPF (`v=spf1` prefix).
- Parse DMARC policy (none / quarantine / reject), SPF mechanisms, DKIM presence.
- Evidence output: per-domain dict with found records and derived posture (strong / weak / missing).

## Acceptance

- Collector runs without new Graph permissions.
- Evidence surfaces each domain's SPF/DKIM/DMARC status.
- SC-8 mapper updates to consume the signal (upgrade from NOT_ADDRESSED to PARTIAL/COMPLIANT based on DMARC policy strength).
- Graceful failure when DNS is unreachable (air-gapped environments).

## Estimate

½ day.

## Priority

High. Free compliance coverage — pure DNS, no tenant changes needed.
