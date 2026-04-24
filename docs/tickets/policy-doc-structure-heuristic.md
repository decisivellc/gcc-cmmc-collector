# Policy document structure heuristic (LLM Phase 0)

## Problem

The policy collector only matches filenames against a keyword table. A stub file named `Access-Control-Policy.docx` with one empty paragraph counts as fully compliant for AC-1. Filenames prove nothing about content. Before spending a week wiring a local LLM (see separate ticket), a heuristic structural check can already catch 50% of "is this an actual policy or a shell?"

## Proposed shape

- Extend `collectors/policies.py` to download each matched document from SharePoint (docx via python-docx, PDF via pypdf).
- For each document, extract text and look for required section headings: **Purpose**, **Scope**, **Roles and Responsibilities**, **Policy Statement**, **Review Cycle / Review Date**.
- Also compute: word count, last-modified date, presence of a signature or approval line.
- Emit per-document structural score: `{sectionsFound: [...], sectionsMissing: [...], wordCount, lastModified, score: 0-5}`.
- Mapper: policy-doc `-1` controls become COMPLIANT only when structural score ≥ 3 AND filename matched. Lower scores produce PARTIAL with specific missing-section gaps.

## Acceptance

- Stub documents (word count < 300 OR < 3 required sections) no longer count as compliant on filename alone.
- Evidence bullet per doc lists found and missing sections.
- Works for both .docx and .pdf; unsupported types emit a note.

## Estimate

1 day.

## Priority

High. Closes an embarrassing weak spot in the current implementation at modest cost.

## Related

Paired with the upcoming LLM-based content review ticket. This is the cheap first pass.
