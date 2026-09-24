# Topic Coverage

Each topic is a module under `src/raze/topics/` exposing tool interfaces and the Raze judgment schemas relevant to it. Interfaces are defined; concrete tool wiring is **proposed** (not yet implemented).

| Topic | Key | Example judgments |
|-------|-----|-------------------|
| Reconnaissance | `recon` | asset relevance, attack-surface ranking |
| Web application | `web` | XSS/SQLi/SSRF exploitability, auth-bypass reachability |
| Network | `network` | service exposure, pivot value |
| Active Directory | `ad` | privilege path value, misconfig impact |
| Cloud | `cloud` | IAM misconfig impact, bucket exposure, metadata SSRF |
| Mobile | `mobile` | insecure storage impact, IPC/exported-component reachability |
| Wireless | `wireless` | rogue-AP feasibility, handshake capture value |
| Exploit development | `exploitdev` | primitive reachability, mitigation-bypass feasibility |
| Reverse engineering | `reversing` | function-of-interest ranking, vuln plausibility |
| Social engineering | `social` | pretext plausibility (authorized assessments only) |
| Cryptography | `crypto` | key/secret impact, weak-algorithm exploitability |

Topic modules must call Raze only for **judgments**, and must route all state-changing actions through the harness authorization gate.

## Analyzer status

Deterministic analyzers (in `src/raze/topics/`) turn collected state into `Signal`s that become finding evidence. Registered in `topics/ANALYZERS`.

| Topic | Analyzers | Status |
|-------|-----------|--------|
| `web` | `ReflectionAnalyzer`, `SecurityHeaderAnalyzer` | **implemented** |
| `recon` | `AssetAnalyzer` | **implemented** |
| `network` | `PortExposureAnalyzer` | **implemented** |
| `cloud` | `BucketExposureAnalyzer`, `MetadataSSRFAnalyzer` | **implemented** |
| `crypto` | `WeakAlgorithmAnalyzer`, `SecretEntropyAnalyzer` | **implemented** |
| `ad` | `KerberoastingAnalyzer`, `DelegationAnalyzer` | **implemented** |
| `mobile` | `AndroidManifestAnalyzer` | **implemented** |
| `wireless` | `WifiSecurityAnalyzer` | **implemented** |
| `exploitdev` | `MitigationAnalyzer` | **implemented** |
| `reversing` | `BinaryTriageAnalyzer` | **implemented** |
| `social` | `EmailSpoofabilityAnalyzer` (authorized assessments only) | **implemented** |

Every taxonomy topic now has at least one analyzer (`PROPOSED_TOPICS == []`). Analyzers stay passive — depth (more detectors per topic, active traffic-sending tools) is the next layer.

Analyzers are passive: they interpret data already collected under an authorized scope and never send traffic to a target.
