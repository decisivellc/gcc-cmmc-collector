"""Tests for structural scoring of policy documents."""

from __future__ import annotations

import policy_review


GOOD_POLICY_TEXT = """
Access Control Policy

1. Purpose
This policy establishes the requirements for controlling access to organizational
information systems and the data they contain. The organization is committed to
protecting confidential information and ensuring only authorized individuals have
access to systems containing CUI. This document describes the mandatory
requirements that all personnel, contractors, and third parties must follow to
preserve the confidentiality, integrity, and availability of organizational
information assets across every environment the organization operates.

2. Scope
This policy applies to all employees, contractors, and third-party vendors who
access organizational systems or data. It covers all systems regardless of
location, including cloud services, on-premises infrastructure, personal and
corporate mobile devices used for business purposes, and any information
processing facility that stores, transmits, or processes CUI or other
sensitive information classified under the organization's classification
standard.

3. Roles and Responsibilities
The Information Security Officer is responsible for maintaining this policy
and ensuring it remains current with regulatory and business requirements.
System administrators implement access controls and review their effectiveness
on a recurring basis. Managers approve access requests for their direct
reports and ensure timely de-provisioning when personnel change roles or leave
the organization. Users are responsible for safeguarding their credentials,
reporting suspected compromise immediately, and using systems only for
authorized purposes.

4. Policy Statement
All access to organizational systems must be authorized and authenticated.
Multi-factor authentication is required for all privileged accounts and for
remote access of any kind. Access is granted based on the principle of least
privilege and reviewed at least quarterly. Privileged access is time-bound
through privileged identity management where supported. Terminated users are
disabled within one business day of departure. Guest and external access is
approved by the Information Security Officer with an explicit expiration
date. Break-glass accounts are documented, stored offline, and monitored for
unauthorized use.

5. Review Cycle
This policy is reviewed annually by the Information Security Officer and
approved by executive leadership. Interim reviews are triggered by material
changes to the regulatory environment, the organizational structure, or the
technology platform. Revisions are tracked in the revision history table
below and communicated to all personnel within thirty days of approval.
"""

STUB_TEXT = "Access Control Policy\n\n(To be written.)"


def test_score_good_policy_hits_all_five_sections():
    result = policy_review.score_document("Access-Control-Policy.docx", GOOD_POLICY_TEXT, None)
    assert result["extracted"] is True
    assert result["score"] == 5
    assert "purpose" in result["sectionsFound"]
    assert "scope" in result["sectionsFound"]
    assert "roles" in result["sectionsFound"]
    assert "policy" in result["sectionsFound"]
    assert "review" in result["sectionsFound"]
    assert result["substantive"] is True
    assert not result["sectionsMissing"]


def test_score_stub_document_fails():
    result = policy_review.score_document("stub.docx", STUB_TEXT, None)
    assert result["extracted"] is True
    assert result["substantive"] is False
    assert result["wordCount"] < policy_review.MIN_WORD_COUNT_SUBSTANTIVE


def test_score_extraction_error_propagates():
    result = policy_review.score_document(
        "broken.docx", None, "extraction error: malformed docx"
    )
    assert result["extracted"] is False
    assert "malformed" in result["error"]
    assert result["score"] == 0
    assert result["sectionsMissing"] == list(policy_review.REQUIRED_SECTIONS.keys())


def test_extract_text_unsupported_file_type():
    text, err = policy_review.extract_text("image.png", b"fake-bytes")
    assert text is None
    assert "unsupported" in err.lower()


def test_extract_text_empty_file():
    text, err = policy_review.extract_text("empty.docx", b"")
    assert text is None
    assert "empty" in err.lower()


def test_phrase_found_matches_numbered_heading():
    # "1. Purpose" is a classic numbered-heading pattern.
    normalized = policy_review._normalize_for_section_match("1. Purpose\nthis is the policy")
    assert policy_review._phrase_found(normalized, "purpose") is True


def test_phrase_not_found_in_unrelated_text():
    normalized = policy_review._normalize_for_section_match("Random text with no structure.")
    assert policy_review._phrase_found(normalized, "purpose") is False
