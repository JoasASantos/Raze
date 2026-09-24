# Raze: Typed, Calibrated Judgments for Authorized Offensive Security

**Joás Santos**
Draft — 2026-09-24. Status: design + harness description. **No comparative results are claimed.**

---

## Abstract

Raze is an agent for **authorized** offensive-security work (penetration tests,
red-team engagements, bug-bounty triage, CTFs) built on a *System One* model —
a small unit of AI intelligence used like a programming primitive that maps
target/engagement state to a **typed, schema-validated judgment** with a
probability. Instead of free-form autonomy, Raze composes narrow judgments
(exploitability, impact, reachability, novelty, next action) in ordinary code,
gates every judgment with **deterministic validators**, and enforces a hard
**authorization boundary** before any judgment or tool runs. This paper describes
the design, the judgment contract, a calibration methodology, and an evaluation
**protocol**. It deliberately reports **no** comparative performance numbers: the
implementation ships an offline stub and a real model backend, but no measured
runs exist yet, and we state explicitly what would be required to make a
defensible claim.

---

## 1. Introduction

Language-model agents are increasingly applied to security testing. The risk is
that a fluent model emits confident prose that a human — or worse, an automated
pipeline — treats as ground truth. Offensive security is unusually unforgiving
here: the model's inputs are **influenced by the target** (page content, banners,
responses), the cost of a false positive is wasted analyst time, and the cost of
an out-of-scope action can be legal.

Raze takes a deliberately narrow stance. The model never plans open-endedly and
never executes tools. It answers one typed question at a time. Code combines the
answers; deterministic validators can overrule them; an authorization gate sits
in front of everything.

## 2. Background and related work

Raze is inspired by agentic security assistants and by the *System One* framing
of small, typed intelligence primitives. Where we reference figures from other
systems (e.g. calibration or latency numbers reported for Jev or Laya), we treat
them strictly as **reported by their sources**, measured on their own tasks,
data, and hardware. We do **not** transplant those numbers to our setting or use
them for comparison; a fair comparison requires paired evaluation on the same
task in the same harness (Section 6).

*Sources to verify before publication (do not cite from memory):* the
browser-use/jev-ultrafast project; NandhaKishorM/laya; ikermoel/open-alternative-jev;
TypeSafe's System One / Jev documentation. Each reference must carry a verifiable
identifier, authors, date, and version, and must actually support the claim it is
attached to. No incomplete citations ("arXiv preprint, 2026").

## 3. System design

Raze has two pieces under one brand:

- **The model — `Raze`.** A callable `judge(schema, context) -> judgment`. Backend-agnostic: an offline `EchoBackend` for tests, a provider-agnostic `LLMBackend` (inject a `complete_fn`), and an `AnthropicBackend`.
- **The agent — `RazeAgent`.** Orchestrates deterministic topic analyzers, the model, and validators, behind the authorization boundary.

Flow: `authorization gate → topic analyzers (evidence signals) → Raze judgments →
deterministic validators → disposition (queued / held / dropped / blocked)`.

### 3.1 Deterministic analyzers

Each topic (web, recon, network, AD, cloud, mobile, wireless, exploit-dev,
reversing, social, crypto) has passive analyzers that turn already-collected
state into `Signal`s (e.g. unescaped reflection, exposed Redis, `alg=none` JWT,
unconstrained delegation). Analyzers send no traffic and never call the model;
their signals become evidence for the judgment.

### 3.2 Deterministic validators

A model probability is never the last word. Validators apply explicit, testable
blocking conditions: an `exploitable` verdict without reproduction evidence is
**blocked**; an unreachable target is **blocked**; a `duplicate`/`theoretical`
novelty is **dropped**; a below-floor probability is **held**.

### 3.3 Authorization boundary

The agent refuses any target not present in an operator-supplied scope, and
records the authorization reference with every artifact. This is enforced in code
before the model sees anything — not as a model instruction.

## 4. The judgment contract

Every judgment is a Pydantic schema plus `probability ∈ [0,1]` and a short
`rationale`. The `probability` is a **model estimate**; it is meaningful only
after calibration (Section 5). The system prompt marks target-influenced evidence
as untrusted data and instructs the model to prefer a low probability and a
conservative verdict over guessing.

## 5. Calibration

We measure calibration with **Expected Calibration Error (ECE)** over a fixed,
labeled test set of `(predicted_probability, correct)` pairs (bucketed average
gap between confidence and accuracy).

**What ECE is not.** ECE is an *aggregate* statistic. It is **not** a ± band on a
single prediction, and one cannot derive precision, recall, false-positive
counts, or analyst-hours from it. As an illustration only: a hypothetical run of
100 findings *cannot* be turned into "≈X true positives" from an ECE value — that
inference is invalid and we do not make it, nor do we attribute such a number to
any model. Precision/recall require measured predictions and labels on the same
test set.

## 6. Evaluation protocol (no results yet)

The implementation includes a benchmark harness, but **no measured runs are
reported**. When results are produced, they must follow this protocol:

1. **One code state.** Freeze and record the git revision for the whole comparison; any change to harness or prompts starts a new experiment.
2. **Fixed parameters.** Model, effort, dataset pinned and recorded in every report.
3. **Multiple runs, alternating order.** A single run is an *observation*, not a demonstration; report mean ± standard deviation across ≥10 runs.
4. **Paired conditions.** Same dataset, same code state, same machine.
5. **Language.** "We observed X ± s on this dataset/code state," never "we demonstrated a general improvement," until variance supports it.

## 7. Security considerations

We make **no** claim that Raze is immune to manipulation. Because evidence is
target-influenced and the model participates in selection and prioritization,
adversarial input **can** bias which findings are surfaced and how they are
ranked. We therefore:

- keep model output **advisory** and gate it with deterministic validators whose blocking conditions are explicit and unit-tested;
- state the exact conditions under which a finding is blocked/held/dropped;
- flag **adversarial-input testing** and **false-negative testing** (a validator wrongly clearing a real issue, or target-crafted input suppressing a finding) as required future work, not solved problems.

## 8. Contribution status

To avoid confusing design with measured result:

| Contribution | Status |
|---|---|
| Typed judgment primitives | implemented |
| Deterministic validator gate | implemented |
| Authorization boundary | implemented |
| Model backends (LLMBackend, AnthropicBackend) | implemented (need credentials to run) |
| Topic analyzers (all 11 topics) | implemented (1–2 detectors each) |
| ECE function | implemented |
| Calibration *results* on a labeled set | **not done** |
| Paired comparison vs. Jev / Laya | **not done** (protocol only) |
| Adversarial / false-negative testing | **not done** |

## 9. Limitations

No measured accuracy, calibration, or latency results exist yet. Analyzers are
shallow (one or two detectors per topic) and passive. The default probabilities
from an LLM backend are uncalibrated until measured. Nothing here has been
evaluated against an adversarial target.

## 10. Conclusion

Raze is a design and a harness for turning offensive-security reasoning into
typed, gated, authorized judgments, with an explicit discipline about what may
and may not be claimed from aggregate metrics. The next milestone is measured,
paired, multi-run evaluation on a labeled dataset under a frozen code state.

## References

To be completed with verified identifiers before any submission. Each entry must
list authors, title, venue/identifier (DOI or stable URL), date, and version, and
must be checked to actually support the claim citing it. Placeholder entries are
intentionally omitted rather than filled with unverifiable citations.
