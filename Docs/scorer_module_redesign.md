# Scorer Module Redesign Specification

## Purpose

This document defines the changes required to make `core/scorer.py` a defensible, standards-informed, evidence-aware scoring engine for the SIH prototype.

The goal is **not** to claim that the final 0–100 score is a universally accepted industry metric. The goal is to produce a transparent **Cryptographic Posture Index** whose security classifications are grounded in standards, whose numerical calibration is explicit and versioned, whose critical findings cannot be hidden by averaging, and whose result can be explained to a judge or investigator from the underlying evidence.

---

## 1. Current scorer: what exists today

The current implementation uses six weighted dimensions:

| Dimension | Current weight |
|---|---:|
| TLS Version | 25% |
| Cipher Suite | 20% |
| Certificate Health | 20% |
| STARTTLS Transition | 15% |
| Forward Secrecy | 10% |
| Protocol Context | 10% |

The score is calculated as:

`S_session = max(0, weighted_component_sum - explicit_penalties)`

The module also contains hand-tuned component scores, hard penalties, risk thresholds, and a volume-weighted harmonic-mean Enterprise Posture Index (EPI).

### Problems to address

1. The numerical weights and component scores are currently engineering choices rather than values derived from a published scoring methodology.
2. Critical failures can be represented both inside component scores and again as penalties, creating possible double-counting.
3. Unknown or unparseable evidence is sometimes assigned a numerical score, which can make missing evidence look like moderate security.
4. The scorer does not distinguish clearly between a standards requirement, a standards recommendation, and a project-specific preference.
5. There is no explicit confidence/evidence-awareness in the final score.
6. Penalties are hard-coded and not versioned as a policy.
7. The EPI treats `byte_count` as traffic importance without documenting the implications of that proxy.
8. Risk thresholds are also calibration decisions and need to be documented and tested.

---

## 2. Design principles for the new scorer

### 2.1 Separate four concepts

The implementation should clearly distinguish:

1. **Evidence** — what was actually observed in the PCAP.
2. **Assessment** — what the evidence means under a selected security policy.
3. **Score** — numerical aggregation of those assessments.
4. **Explanation** — human-readable reasoning with references.

The scorer should not reinterpret packet-level evidence itself.

### 2.2 Standards define security meaning, not our arbitrary 0–100 values

Use standards to establish whether a property is prohibited, required, recommended, discouraged, or acceptable. The conversion from those categories into 0–100 values is a **project calibration** and must be documented as such.

Primary evidence sources:

- RFC 9325 — secure TLS/DTLS deployment recommendations.
- RFC 8996 — TLS 1.0/1.1 deprecation.
- RFC 8446 — TLS 1.3 specification.
- RFC 8314 — TLS for email submission and access.
- NIST SP 800-52 Rev. 2 — TLS implementation guidance and certificate profile.
- NIST SP 800-57 — cryptographic strength/key-size guidance where applicable.

Do not claim that any source specifies the project's exact weights unless it actually does.

### 2.3 Prefer evidence-aware scoring over optimistic defaults

Unknown, missing, truncated, or malformed observations should become `INCONCLUSIVE` / `NOT_ASSESSED`, not automatically become a medium score.

A parser failure is not evidence that a configuration is secure or insecure.

### 2.4 Avoid double-counting

A security property should have one primary scoring home. For example:

- TLS protocol version → TLS Version component.
- Record-protection algorithm → Cipher component.
- Key exchange forward secrecy → Forward Secrecy component.
- Certificate properties → Certificate Health component.
- Upgrade integrity/downgrade evidence → STARTTLS component.
- Email-port/protocol usage → Protocol Context component.

Critical findings can additionally impose **score caps/floors**, but they should not be treated as repeated full penalties for the same underlying fact.

---

## 3. Recommended new scoring architecture

```text
Session Evidence
      |
      v
Standards/Policy Evaluation
      |
      +-------------------------------+
      |                               |
      v                               v
Six Quality Components         Critical Finding Assessment
      |                               |
      v                               v
Weighted Quality Score         Score Caps / Severe Deductions
      |                               |
      +---------------+---------------+
                      |
                      v
               Final 0–100 score
                      |
                      v
             Risk Tier + Confidence
                      |
                      v
              Explanation object
```

The explanation should be generated from structured scoring metadata, **not by asking an LLM to invent a justification after the score is calculated**.

---

## 4. Introduce a versioned scoring policy

Replace the current collection of module-level constants with a structured `ScoringPolicy` object or equivalent configuration.

Example conceptual policy:

```yaml
policy_id: crypto-posture-v1
policy_version: 1.0
baseline:
  - RFC 9325
  - RFC 8996
  - RFC 8314
  - NIST SP 800-52r2
weights:
  tls_version: 0.25
  cipher_suite: 0.20
  certificate_health: 0.20
  starttls_transition: 0.15
  forward_secrecy: 0.10
  protocol_context: 0.10
risk_thresholds:
  low: 80
  medium: 55
  high: 30
critical_cap: 29
```

The exact values should be finalized only after calibration and testing.

Persist the policy ID/version alongside every analysis result so old results remain reproducible even after scoring rules change.

---

## 5. Redesign the six component scores

### 5.1 TLS Version

Current values should not be treated as standards-derived constants.

Recommended semantics:

| Version | Classification | Suggested score range |
|---|---|---:|
| TLS 1.3 | Preferred modern | 95–100 |
| TLS 1.2 | Secure when correctly configured | 90–95 |
| TLS 1.1 | Prohibited/deprecated | 0–20 |
| TLS 1.0 | Prohibited/deprecated | 0–10 |
| SSLv3 | Prohibited/broken | 0 |
| SSLv2 | Prohibited/broken | 0 |
| Unknown | Inconclusive | N/A |

RFC 9325 states that SSLv2/SSLv3/TLS 1.0/TLS 1.1 must not be negotiated, while TLS 1.2 remains a secure option when correctly configured and TLS 1.3 is preferred. The numerical mapping above is a project calibration, not a quote from RFC 9325.

Do not award a numeric 50 simply because the version is unknown.

### 5.2 Cipher Suite

Make this dimension measure the strength/modernity of the **record protection**, not forward secrecy.

Recommended conceptual categories:

- Modern AEAD (AES-GCM, ChaCha20-Poly1305) → 95–100.
- Acceptable legacy constructions → intermediate range.
- Deprecated/weak 3DES → low score.
- RC4/NULL/EXPORT → 0.
- Unknown/unrecognized → N/A.

Use structured cipher metadata rather than substring matching wherever possible.

### 5.3 Certificate Health

Split the assessment into:

- Validity window.
- Public-key algorithm and strength.
- Signature algorithm.
- Chain/trust properties.
- Hostname/SAN consistency where available.

Avoid treating self-signed as universally equivalent to cryptographic weakness. Label it as context-dependent unless the selected policy explicitly requires a trusted public CA chain.

Use algorithm-specific security-strength rules rather than comparing raw bit lengths across RSA, EC, and other key types as though they were equivalent.

### 5.4 STARTTLS Transition

Measure transition integrity rather than “TLS quality.”

Recommended semantics:

- Implicit TLS → 100.
- Successfully negotiated STARTTLS on an appropriate port → high score, potentially 90–100.
- STARTTLS advertised but unused → substantially lower score.
- Failed transition → near-zero.
- Confirmed attack evidence → 0 plus critical score cap.
- Possible stripping/inconclusive evidence → severe deduction, but not the same certainty as a confirmed attack.

Do not penalize successful SMTP STARTTLS simply because implicit TLS is conceptually cleaner. Protocol context should carry the preference where appropriate.

### 5.5 Forward Secrecy

Use explicit key-exchange properties:

- ECDHE → highest.
- DHE → high but below preferred ECDHE unless policy says otherwise.
- Static RSA → 0 / severe finding.
- Unknown → N/A.

Keep this separate from the cipher score.

### 5.6 Protocol Context

Measure whether the protocol/port/channel combination is appropriate.

Do not collapse “recommended” and “mandatory” behavior into the same severity.

For example, RFC 8314's use of implicit TLS for mail access should be represented differently from an outright plaintext security failure on a protected email workflow.

---

## 6. Replace additive critical penalties with controlled caps where appropriate

The current implementation subtracts large penalties such as:

- Plaintext: 60.
- SSLv2/SSLv3: 50.
- Buffer injection: 50.
- STARTTLS stripping: 40.
- RC4/NULL/EXPORT: 30.

These should be reconsidered because component scores may already reflect the same underlying condition.

Preferred approach:

```text
quality_score = weighted component score

critical finding:
    apply score cap or bounded deduction

final_score = min(quality_score, applicable_cap)
```

Examples of policy semantics:

- Confirmed plaintext → final score cap near 0/critical range.
- SSLv2/SSLv3 → final score cap near 0/critical range.
- Confirmed STARTTLS buffer injection → critical cap.
- Confirmed STARTTLS stripping → critical cap.
- Weak/deprecated cipher → meaningful cap/deduction, but avoid counting it through every component.

Caps are easier to explain than arbitrary large deductions and prevent a catastrophic flaw from being averaged away.

---

## 7. Introduce assessment status and confidence

Every component should ideally expose:

```text
status: PASS | DEGRADED | VIOLATION | INCONCLUSIVE | NOT_APPLICABLE
confidence: HIGH | MEDIUM | LOW
reason: string
rule_ids: []
evidence_refs: []
```

This enables cases such as:

```text
TLS version:
  status = INCONCLUSIVE
  confidence = LOW
  reason = "Handshake truncated before ServerHello."
```

rather than silently assigning a score of 50.

The final result should also contain an overall confidence level derived from the availability and quality of the evidence.

---

## 8. Make scoring explanations first-class data

Add a structured explanation model to `scorer.py`, for example conceptually:

```json
{
  "component": "tls_version",
  "observed": "TLS1.2",
  "assessment": "PASS",
  "component_score": 92,
  "weight": 0.25,
  "contribution": 23.0,
  "reason": "TLS 1.2 is an acceptable secure baseline when correctly configured.",
  "references": ["RFC 9325 §3.1.1"],
  "confidence": "HIGH"
}
```

For every component, preserve:

- observed value;
- classification;
- component score;
- weight;
- weighted contribution;
- reason;
- policy/rule ID;
- evidence reference;
- confidence.

This object becomes the authoritative source for the frontend explanation panel.

---

## 9. Frontend explanation panel

Add an “**Why this score?**” section to the frontend.

### Recommended UI

```text
CRYPTographic Posture Score
82 / 100   MEDIUM
Confidence: HIGH

Why?

TLS Version             92 × 25% = 23.0
✓ TLS 1.2
   RFC 9325 §3.1.1

Cipher Suite           100 × 20% = 20.0
✓ AES-128-GCM

Certificate             78 × 20% = 15.6
⚠ Certificate is self-signed

STARTTLS                90 × 15% = 13.5
✓ STARTTLS negotiated successfully

Forward Secrecy        100 × 10% = 10.0
✓ ECDHE

Protocol Context        70 × 10% = 7.0
⚠ STARTTLS used on IMAP access port

No critical caps applied.
```

Each finding should have an expandable “Evidence” and “Reference” area.

### Critical finding example

```text
CRITICAL — Final score capped at 25

STARTTLS stripping evidence detected.

Observed:
Client requested STARTTLS, but no server capability advertisement
was observed in the reconstructed stream.

Assessment:
Possible/confirmed stripping depending on evidence confidence.

Reference:
RFC 3207 / RFC 8314 / project attack-detection policy
```

The UI must never imply that an RFC explicitly assigns the score value.

---

## 10. Evidence references: what the frontend should cite

Use authoritative sources first:

1. RFC Editor versions of the relevant RFCs.
2. NIST publications and official NIST PDFs.
3. Research papers for attack-specific claims where applicable.
4. Project policy documentation for project-specific score calibration.

For each explanation, distinguish:

- **Standards evidence:** what the external standard says.
- **Observed evidence:** what the PCAP contained.
- **Project calculation:** how those facts became a numerical score.

This three-way distinction is essential.

Example:

> Observed: TLS 1.0 was negotiated.
>
> Standard basis: RFC 9325 says TLS 1.0 must not be negotiated.
>
> Project scoring: our `crypto-posture-v1` policy assigns TLS 1.0 a component score of 5/100.

That is transparent and defensible.

---

## 11. Weight methodology

Do **not** say the six current weights were “derived from NIST” or “from RFC 9325.” They are not specified there.

Instead implement a documented calibration process.

### Proposed process

#### Step 1 — Establish dimension relevance

Use standards to justify why each dimension exists.

#### Step 2 — Define security categories

For each dimension identify:

- prohibited/broken;
- insecure/deprecated;
- acceptable;
- preferred;
- unknown.

#### Step 3 — Set initial expert weights

Use a transparent engineering rationale, e.g. protocol version and cipher selection are heavily weighted because they directly govern protocol/record security; certificate health and STARTTLS transition are separately material; forward secrecy and protocol context remain distinct supporting dimensions.

#### Step 4 — Benchmark

Create a controlled benchmark set containing known-good, degraded, and clearly-bad sessions.

#### Step 5 — Sensitivity analysis

Perturb weights within reasonable ranges and verify that obvious classifications remain stable.

Example:

```text
TLS weight: 20–30%
Cipher: 15–25%
Certificate: 15–25%
STARTTLS: 10–20%
Forward secrecy: 5–15%
Protocol context: 5–15%
```

#### Step 6 — Version the calibration

Call the resulting policy something like `crypto-posture-v1`.

The deck should state that the numerical model is a **standards-informed, empirically checked prototype calibration**, not a universal industry standard.

---

## 12. Risk tiers

Current thresholds are:

- LOW ≥ 80
- MEDIUM ≥ 55
- HIGH ≥ 30
- CRITICAL < 30

These are also project calibration decisions.

Keep them only if benchmark testing shows they separate the demo scenarios clearly.

Test explicitly that:

- clean sessions consistently fall in LOW;
- moderate configuration problems fall in MEDIUM/HIGH;
- plaintext and confirmed critical attacks fall in CRITICAL.

Consider making a critical attack finding capable of forcing `CRITICAL` irrespective of numerical score.

---

## 13. Enterprise Posture Index redesign

The current EPI is a volume-weighted harmonic mean using `byte_count` as the volume proxy. fileciteturn6file0L295-L330

This is mathematically reasonable as a conservative aggregation mechanism, but the project must document the assumption that **traffic volume is being used as a proxy for exposure/importance**.

Recommended improvements:

- expose the weighting method in the policy;
- allow future alternatives such as session-count or business-criticality weighting;
- report both EPI and the number of critical/high sessions;
- ensure zero-score sessions are handled explicitly rather than only through an epsilon;
- preserve per-session contribution to EPI for explanation.

The frontend should be able to answer:

> “Why is the enterprise score low?”

Example:

```text
EPI = 61

18 sessions analyzed
4 critical
3 high

Largest contributors:
- SMTP plaintext: 41 MB
- STARTTLS failures: 12 MB
- TLS 1.2 secure sessions: 8 MB
```

---

## 14. Testing requirements

Create a scoring test matrix.

### TLS

- TLS 1.3 secure.
- TLS 1.2 secure.
- TLS 1.2 + weak cipher.
- TLS 1.1.
- TLS 1.0.
- SSLv3/SSLv2 if test data can be safely generated.
- Unknown/incomplete TLS version.

### Cipher

- AES-GCM.
- ChaCha20-Poly1305.
- CBC.
- 3DES.
- RC4.
- NULL.
- Unknown cipher.

### Certificate

- Valid strong certificate.
- Expired certificate.
- Not-yet-valid.
- SHA-1.
- MD5.
- Weak RSA.
- EC with appropriate key strength.
- Self-signed internal certificate.
- Missing/incomplete certificate.

### STARTTLS

- Implicit TLS.
- Successful STARTTLS.
- Advertised but unused.
- Failed STARTTLS.
- Possible stripping.
- Confirmed stripping test case.
- Buffer injection.
- Incomplete negotiation.

### Scoring behavior

Verify:

- scores remain 0–100;
- critical findings cannot accidentally produce a “LOW” risk tier;
- unknown evidence does not masquerade as a passing score;
- no underlying condition is double-counted accidentally;
- small weight changes do not dramatically reorder obvious benchmark cases.

---

## 15. Database/persistence implications

A database is **not required inside the scorer itself**.

If SQLite is later introduced, persist:

- capture SHA-256;
- analysis timestamp;
- scoring policy ID/version;
- session ID;
- component scores;
- findings;
- final score;
- confidence;
- EPI;
- report version.

Do not put raw packet bytes into the scoring database by default. Keep the original PCAP immutable and treat the database as an analysis-result/provenance store.

---

## 16. Recommended refactor of `scorer.py`

Target conceptual structure:

```text
scorer.py
│
├── policy.py / ScoringPolicy
│   ├── weights
│   ├── category scores
│   ├── critical caps
│   ├── risk thresholds
│   └── policy version
│
├── component assessment functions
│   ├── assess_tls_version()
│   ├── assess_cipher()
│   ├── assess_certificate()
│   ├── assess_starttls()
│   ├── assess_forward_secrecy()
│   └── assess_protocol_context()
│
├── score aggregation
│   ├── weighted score
│   ├── critical caps
│   └── confidence aggregation
│
├── explanation generation
│   └── structured ScoreExplanation objects
│
└── EPI aggregation
    └── enterprise explanation
```

Prefer small pure assessment functions over one function containing both classification and arithmetic.

---

## 17. What must NOT be claimed in the pitch

Do not claim:

- “The 25/20/20/15/10/10 weights come from NIST.”
- “Our 0–100 score is an industry-standard metric.”
- “A score of 82 has a universally defined meaning.”
- “RFC 9325 assigns TLS 1.3 a score of 100.”
- “A missing STARTTLS advertisement proves a MITM.”

Instead claim:

> “We use a standards-informed, versioned scoring policy that converts observed cryptographic properties into an explainable 0–100 posture index.”

And:

> “Every score can be decomposed into observed evidence, standards basis, project calibration, and confidence.”

---

## 18. Implementation priority

### P0 — must do

1. Remove misleading unknown=50 style defaults.
2. Separate quality scoring from critical failure handling.
3. Document the weights as calibration choices.
4. Add structured per-component explanations.
5. Add policy versioning.
6. Fix double-counting risks.
7. Add benchmark/sensitivity tests.
8. Make risk thresholds policy-driven.

### P1 — strongly recommended

9. Add confidence and assessment status.
10. Improve certificate/key-type handling.
11. Add score caps for catastrophic findings.
12. Add EPI contribution/explanation data.
13. Add SQLite persistence for analysis history/provenance.

### P2 — future

14. Expert-elicitation study for weight calibration.
15. Statistical calibration against a larger labeled dataset.
16. Multiple organizational policy profiles.
17. Historical posture trend analysis.
18. SIEM integration.

---

## 19. Reference set for implementation

Use official/primary references wherever possible:

- RFC 9325 — Recommendations for Secure Use of TLS/DTLS: https://www.rfc-editor.org/rfc/rfc9325.html
- RFC 8996 — Deprecating TLS 1.0 and TLS 1.1: https://www.rfc-editor.org/rfc/rfc8996.html
- RFC 8314 — Cleartext Considered Obsolete: https://www.rfc-editor.org/rfc/rfc8314.html
- NIST SP 800-52 Rev. 2 — Guidelines for TLS Implementations: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-52r2.pdf
- NIST SP 800-57 Part 3 Rev. 1 — Application-Specific Key Management Guidance: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt3r1.pdf

RFC 9325 explicitly treats SSLv2/SSLv3/TLS 1.0/TLS 1.1 as versions that must not be negotiated, while retaining TLS 1.2 as a secure option when correctly configured and preferring TLS 1.3. NIST SP 800-52 Rev. 2 provides a server certificate profile including minimum cryptographic-strength guidance and certificate requirements.

---

## Final target

The finished scorer should allow the team to answer three questions in one screen:

1. **What did we observe?**
2. **Why is it considered secure/insecure?**
3. **Why did that produce this particular numerical score?**

The score should therefore be treated as an **explainable, standards-informed project metric**, with every numerical choice traceable to a versioned policy and every security conclusion traceable to observed evidence and authoritative references.
