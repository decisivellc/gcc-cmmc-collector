# Policy document content review via local LLM (LLM Phase 1)

## Problem

Filename matching and section-heading heuristics (Phase 0 ticket) prove a document *exists* with the right shape. They don't prove the document actually *addresses* the NIST 800-171A required elements for that control. A fully-structured policy that forgets to assign responsibility or omits review cadence should fail the control — today it passes.

## Proposed shape

### Corpus (the real work)

Hand-curate `docs/nist-800-171a-checkpoints.json`: for each of the 13 `-1` controls, list the specific required elements per the NIST 800-171A assessment guide. Example for AC-1:

```json
"AC-1": [
  {"element": "Assigns responsibility for access control policy maintenance", "keywords": ["responsible", "owner", "maintained by"]},
  {"element": "Defines scope of coverage (users/systems)", "keywords": ["scope", "applies to"]},
  {"element": "Specifies review cadence", "keywords": ["review", "annually", "reviewed"]},
  {"element": "Addresses policy dissemination", "keywords": ["communicate", "distribute", "acknowledge"]}
]
```

### Model

Local via Ollama sidecar (docker-compose service). Default model: Llama 3.1 8B instruct or similar. Container grows ~5 GB for weights.

### Pipeline

1. For each matched policy doc, extract text.
2. For each assessment checkpoint, prompt: "Given this policy text, is the element X addressed? Quote the supporting passage if yes."
3. Structured output: `{element, present: bool, quote: str, confidence: str}`.
4. Roll up per document: score = addressed elements / total elements.
5. Mapper: policy-doc `-1` controls reflect the checkpoint coverage (not just filename / structure).

## Acceptance

- Container ships with the model pre-downloaded, or pulls on first run with a clear progress message.
- `/run` becomes async (background job + polling) since review can take minutes for a full library.
- Report shows per-document checkpoint coverage: which elements are addressed, which are missing, supporting quotes.
- Works fully offline — no cloud API calls.
- Accuracy acceptable against 10 hand-scored policy documents used as a test harness.

## Risks and tradeoffs

- **Model hallucination**: 8B instruct models will sometimes say "present" on a stub. Mitigate with a confidence score + manual-verify callout for anything < "high".
- **Corpus maintenance**: the checkpoints file is the value center and the ongoing liability. Keep it in source control and make updates part of the normal PR flow.
- **Runtime**: reviewing 37 documents × 6 checkpoints × 8B model on CPU ≈ 5-15 minutes. Acceptable for scheduled runs; user-triggered runs need a spinner.
- **Image size**: +5 GB. Offer a "slim" image without the model for users who only want filename + heuristic matching.

## Estimate

1 week.

## Priority

Medium. Very high ceiling on value but only unlocks after the cheaper Phase 0 heuristic is in place.

## Depends on

Policy document structure heuristic ticket (Phase 0).
