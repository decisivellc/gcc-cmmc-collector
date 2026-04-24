"""Email security collector — SPF / DKIM / DMARC DNS checks.

Evidence for NIST 800-171 3.13.15 (authenticity of communications
sessions) and the broader anti-spoofing story. Pure DNS — no new Graph
permissions beyond ``Directory.Read.All`` which the tool already holds.

For each verified tenant domain we look up:
- SPF (TXT at the apex beginning with ``v=spf1``)
- DMARC (TXT at ``_dmarc.<domain>`` beginning with ``v=DMARC1``)
- DKIM (TXT at ``selector1._domainkey.<domain>`` and ``selector2._domainkey.<domain>``
  — the default Microsoft 365 selectors)

The collector never fails hard on DNS errors — missing records are a
finding, not a collection warning.
"""

from __future__ import annotations

import logging
from typing import Any

from collectors.base import BaseCollector
from graph_client import GraphClient

logger = logging.getLogger(__name__)


MICROSOFT_DKIM_SELECTORS = ("selector1", "selector2")


class EmailSecurityCollector(BaseCollector):
    name = "email_security"

    def __init__(self, client: GraphClient, domains: list[str] | None = None) -> None:
        super().__init__(client)
        self.configured_domains = [d.strip() for d in (domains or []) if d and d.strip()]

    def collect(self) -> dict[str, Any]:
        domains = self.configured_domains or self._list_tenant_domains()
        results: list[dict[str, Any]] = []
        for domain_info in domains:
            name = domain_info if isinstance(domain_info, str) else domain_info.get("id") or domain_info.get("name")
            if not name:
                continue
            results.append(_check_domain(name, dns_resolver=_resolve_txt))
        summary = _summarize(results)
        return {"available": True, "domains": results, "summary": summary}

    def _list_tenant_domains(self) -> list[dict[str, Any]]:
        """Return verified domains via /domains. Only include verified ones —
        unverified domains in the tenant won't have DNS we control."""
        raw = self._safe_get_all("/domains")
        out: list[dict[str, Any]] = []
        for d in raw:
            if not d.get("isVerified"):
                continue
            # Skip the default onmicrosoft.us domain; SPF/DMARC is Microsoft-managed there.
            dom_id = (d.get("id") or "").lower()
            if dom_id.endswith(".onmicrosoft.us") or dom_id.endswith(".onmicrosoft.com"):
                continue
            out.append(d)
        return out


def collect(client: GraphClient, domains: list[str] | None = None) -> dict[str, Any]:
    collector = EmailSecurityCollector(client, domains=domains)
    result = collector.collect()
    if collector.warnings:
        result["_collectionWarnings"] = collector.warnings
    return result


def _resolve_txt(name: str) -> list[str]:
    """Return a list of TXT record strings for ``name``, or [] on failure.

    Wrapping dnspython so tests can inject a stub resolver without importing
    the real library.
    """
    try:
        import dns.resolver
    except ImportError:
        logger.warning("dnspython not installed; email_security collector can't resolve %s", name)
        return []
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5.0)
    except Exception as exc:
        logger.debug("dns lookup failed for %s: %s", name, exc)
        return []
    records: list[str] = []
    for rdata in answers:
        # TXT records come as sequences of bytes that need joining.
        try:
            parts = [b.decode("utf-8", errors="replace") for b in rdata.strings]
        except AttributeError:
            parts = [str(rdata)]
        records.append("".join(parts))
    return records


def _check_domain(domain: str, dns_resolver) -> dict[str, Any]:
    spf = _evaluate_spf(dns_resolver(domain))
    dmarc = _evaluate_dmarc(dns_resolver(f"_dmarc.{domain}"))
    dkim = _evaluate_dkim(domain, dns_resolver)
    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "posture": _posture(spf, dmarc, dkim),
    }


def _evaluate_spf(txt_records: list[str]) -> dict[str, Any]:
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            ending = "soft-fail" if "~all" in record else "fail" if "-all" in record else "neutral" if "?all" in record else "unknown"
            includes = [tok.split(":", 1)[1] for tok in record.split() if tok.lower().startswith("include:")]
            return {
                "present": True,
                "record": record,
                "ending": ending,
                "strict": ending == "fail",
                "includes": includes,
            }
    return {"present": False, "record": None, "strict": False}


def _evaluate_dmarc(txt_records: list[str]) -> dict[str, Any]:
    for record in txt_records:
        lowered = record.lower()
        if lowered.startswith("v=dmarc1"):
            tags = {}
            for tok in record.split(";"):
                if "=" in tok:
                    k, v = tok.strip().split("=", 1)
                    tags[k.strip().lower()] = v.strip()
            policy = tags.get("p", "none").lower()
            return {
                "present": True,
                "record": record,
                "policy": policy,
                "strict": policy in ("quarantine", "reject"),
                "subdomainPolicy": tags.get("sp"),
                "aggregateReportUri": tags.get("rua"),
            }
    return {"present": False, "record": None, "strict": False}


def _evaluate_dkim(domain: str, dns_resolver) -> dict[str, Any]:
    selectors: list[dict[str, Any]] = []
    any_present = False
    for selector in MICROSOFT_DKIM_SELECTORS:
        records = dns_resolver(f"{selector}._domainkey.{domain}")
        record_text = next(
            (r for r in records if "v=dkim1" in r.lower() or "k=rsa" in r.lower() or "p=" in r.lower()),
            None,
        )
        present = bool(record_text)
        if present:
            any_present = True
        selectors.append({"selector": selector, "present": present, "record": record_text})
    return {"present": any_present, "selectors": selectors}


def _posture(spf: dict[str, Any], dmarc: dict[str, Any], dkim: dict[str, Any]) -> str:
    if spf.get("strict") and dmarc.get("strict") and dkim.get("present"):
        return "strong"
    if spf.get("present") and dmarc.get("present") and dkim.get("present"):
        return "partial"
    if not spf.get("present") and not dmarc.get("present") and not dkim.get("present"):
        return "missing"
    return "weak"


def _summarize(domains: list[dict[str, Any]]) -> dict[str, Any]:
    by_posture: dict[str, int] = {"strong": 0, "partial": 0, "weak": 0, "missing": 0}
    for d in domains:
        by_posture[d["posture"]] = by_posture.get(d["posture"], 0) + 1
    return {
        "domainsChecked": len(domains),
        "postureBreakdown": by_posture,
        "allStrong": bool(domains) and by_posture.get("strong", 0) == len(domains),
    }
