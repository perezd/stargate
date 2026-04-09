# Accepted Risks

Risks evaluated by the expert panel and accepted with documented mitigations.

## TOCTOU in File Retrieval Path Validation

**Risk:** Between `filepath.EvalSymlinks` and the actual file read, a symlink target could be swapped by a concurrent local process.

**Mitigation:** An attacker with the ability to race symlinks already has local file access (stargate is localhost-only), so this is not a privilege escalation. `denied_paths` provides a secondary check.

**Panel:** R2-RedTeam-4, R2-LLMSec-8

## Base64-Encoded Secrets Not Detected by Scrubbing

**Risk:** Secrets encoded as base64 (e.g., `echo "c2stYW50LWFiYzEyMw==" | base64 -d`) bypass plaintext regex patterns.

**Mitigation:** Base64 detection is computationally expensive and error-prone (high false positive rate). The LLM is a classification tool, not an exfiltration channel — seeing an encoded token in the prompt does not create a data leak path. Defense-in-depth: reasoning truncation (200 chars in API, 1000 chars in corpus) limits what propagates.

**Panel:** R2-LLMSec-4

## Variable Names May Reveal Secret Existence

**Risk:** Env var names like `PROD_DB_PASSWORD` are not scrubbed (only values are). The name reveals that production database credentials exist.

**Mitigation:** Variable names are necessary for the LLM to reason about what the command does. Scrubbing names would remove essential classification context. The name alone (without the value) is not a credential.

**Panel:** R2-LLMSec-4

## `files_requested` Reveals LLM Reasoning Patterns

**Risk:** The `files_requested` field in the API response shows which files the LLM asked to inspect, revealing what the LLM considers relevant for classification.

**Mitigation:** This field is useful for debugging, transparency, and audit trails. An attacker who can see API responses already has local access. The information value to operators outweighs the minor information leak.

**Panel:** R2-LLMSec-12

## Precedent Reasoning Accumulation

**Risk:** LLM reasoning stored in the corpus and injected into future prompts could accumulate sensitive file content fragments over time.

**Mitigation:** Multiple controls bound this: (1) reasoning scrubbed for secrets before storage, (2) `corpus.max_reasoning_length` (1000 chars) truncates stored reasoning, (3) `max_precedents_per_decision` caps per-signature precedent volume, (4) TTL/decay (90d) ensures natural expiration, (5) `max_response_reasoning_length` (200 chars) limits what reaches API responses.

**Panel:** R2-AppSec-5, R2-LLMSec-6
