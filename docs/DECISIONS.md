# The Raze decision surface

Raze is a **decision engine for offensive security**, in the line of Jev and Laya:
at every step of an engagement there is a typed decision to make, and Raze makes
it — fast, chained, calibrated, and gated. This document maps the full surface:
the kill-chain phases, the decisions in each, the vulnerability classes they cover,
and which decisions require a human before they are acted on.

Raze **answers** decisions. It never autonomously executes a human-gated one.
The hard authorization boundary (`raze.authz`) sits in front of everything.

## Decisions by kill-chain phase

Each row is a `DecisionKind` in `raze.killchain.DECISION_REGISTRY`, bound to a
typed judgment schema. "Human?" = requires explicit operator approval to act.

| Phase | Decision | Judgment | Human? | Question |
|-------|----------|----------|:------:|----------|
| recon | `in_scope` | `InScope` | no | In scope and worth engaging? |
| enumeration | `asset_priority` | `AssetPriority` | no | How much attention does this asset deserve? |
| vuln_analysis | `exploitability` | `Exploitability` | no | Exploitable in this context? |
| vuln_analysis | `impact` | `Impact` | no | What does exploitation grant? |
| vuln_analysis | `reachability` | `Reachability` | no | Is it reachable? |
| vuln_analysis | `novelty` | `Novelty` | no | Novel / known / duplicate / theoretical? |
| vuln_analysis | `combined` | `CombinedJudgment` | no | Fast one-call judgment (all of the above) |
| exploitation | `technique_selection` | `TechniqueSelection` | **yes** | Which technique to attempt? |
| exploitation | `go_no_go` | `GoNoGo` | **yes** | Safe/authorized to execute now? |
| lateral_movement | `next_pivot` | `NextAction` | **yes** | Where to pivot next? |
| privilege_escalation | `privesc_path` | `NextAction` | **yes** | Which privesc path? |
| reporting | `severity` | `Impact` | no | Severity to report at? |
| reporting | `report_inclusion` | `GoNoGo` | no | Include in the report? |

Any state-changing / offensive step is human-gated (`human_gated_kinds()`).

## Vulnerability classes → the decision Raze makes

Raze's topic analyzers (`raze.topics`) surface signals for these classes; the
decision layer turns signals + context into a verdict, impact, and priority.

| Class (topic) | Examples | Primary decision |
|---------------|----------|------------------|
| Injection (web) | XSS, SQLi, command inj, SSTI, SSRF, open redirect | exploitability + impact |
| Access control (web/api) | IDOR/BOLA, auth bypass, mass assignment | exploitability + reachability |
| Network exposure | unauth Redis/Mongo/Docker, telnet, RDP/SMB | exploitability + next_pivot |
| Cryptography | JWT alg=none, weak hash/cipher, low-entropy keys | exploitability (impact by what the key grants) |
| Active Directory | kerberoasting, AS-REP, unconstrained delegation | exploitability + privesc_path |
| Cloud | public buckets, metadata SSRF, IAM misconfig | exploitability + impact |
| Mobile | debuggable, cleartext, exported components | exploitability |
| Wireless | open/WEP/WPA, WPS | exploitability |
| Exploit dev | missing NX/ASLR/PIE/canary + a primitive | exploitability (feasibility) + go_no_go |
| Reversing | dangerous imports, embedded secrets | novelty + impact |
| Social | spoofable domains (SPF/DKIM/DMARC), look-alikes | impact (authorized assessments only) |

## Offensive tasks → decisions

- **Triage a bug-bounty report** → exploitability + novelty (dedupe) + severity.
- **Prioritize an engagement** → `raze plan`: decide all, correlate attack chains, rank.
- **Choose what to hit first** → priority score (severity × exploitability × novelty × reachability + signals + reproduction).
- **Decide to fire an exploit** → `go_no_go` + `technique_selection` (human-gated).
- **Move laterally / escalate** → `next_pivot` / `privesc_path` (human-gated).
- **Write the report** → `severity` + `report_inclusion`.

## Principles carried through every decision

1. **Typed, not prose.** Every decision is a schema-validated judgment.
2. **Calibrated.** Probabilities are measured (ECE) and rescaled (`raze.calibrator`).
3. **Chained + decisive.** `raze.decide` short-circuits and scores multi-factor.
4. **Gated.** Deterministic validators can overrule; offensive steps need a human.
5. **Authorized only.** Nothing acts outside the operator-supplied scope.
