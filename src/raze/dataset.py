"""Training-dataset export for a dedicated Raze model (the fine-tune milestone).

Turns labeled findings into supervised examples for training/evaluating a
dedicated judgment model. Inputs are built with the SAME prompt builders the
inference path uses (raze.backends.llm), so what a model learns matches what it
sees at run time. Targets are the ground-truth judgment.

Two export formats:
- generic JSONL:  {"input": {"system","user"}, "target": {...}, "meta": {...}}
- messages JSONL: {"messages": [system, user, assistant(target json)]} — SFT shape

Note on probabilities: SFT targets use hard labels (probability 1.0 for the
correct verdict). Probability *calibration* is handled post-hoc by
raze.calibrator, not learned from these hard targets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from raze.backends.llm import build_system_prompt, build_user_prompt
from raze.bench import BenchCase
from raze.cvss import severity_rating
from raze.judgments import Exploitability, ExploitVerdict, JudgmentContext
from raze.topics import analyze


@dataclass
class TrainingExample:
    system: str
    user: str
    target: dict
    meta: dict


def build_examples(cases: list[BenchCase], *, run_analyzers: bool = True) -> list[TrainingExample]:
    examples: list[TrainingExample] = []
    for case in cases:
        f = case.finding
        signals = analyze(f.topic, f.state) if run_analyzers else []
        ctx = JudgmentContext(
            task=f"Assess finding: {f.title}",
            topic=f.topic,
            state=f.state,
            evidence=list(f.evidence) + [str(s) for s in signals],
        )
        verdict = (
            ExploitVerdict.exploitable if case.exploitable_truth else ExploitVerdict.not_exploitable
        )
        cm = case.meta or {}
        target = {
            "probability": 1.0,
            "rationale": "",
            "verdict": verdict.value,
            "preconditions": [],
        }
        # Ground the training target in CWE/CVSS/class when the dataset provides it.
        if cm.get("cvss_score") is not None:
            target["severity"] = severity_rating(cm["cvss_score"])
        if cm.get("cwe"):
            target["cwe"] = cm["cwe"]
        if cm.get("vuln_class"):
            target["vuln_class"] = cm["vuln_class"]
        examples.append(
            TrainingExample(
                system=build_system_prompt(Exploitability),
                user=build_user_prompt(ctx),
                target=target,
                meta={
                    "target": f.target,
                    "topic": f.topic,
                    "title": f.title,
                    "cwe": cm.get("cwe"),
                    "vuln_class": cm.get("vuln_class"),
                    "cvss_vector": cm.get("cvss_vector"),
                    "difficulty": cm.get("difficulty"),
                },
            )
        )
    return examples


def to_jsonl_generic(examples: list[TrainingExample]) -> str:
    return "\n".join(
        json.dumps(
            {"input": {"system": e.system, "user": e.user}, "target": e.target, "meta": e.meta},
            ensure_ascii=False,
        )
        for e in examples
    )


def to_jsonl_messages(examples: list[TrainingExample]) -> str:
    lines = []
    for e in examples:
        lines.append(
            json.dumps(
                {
                    "messages": [
                        {"role": "system", "content": e.system},
                        {"role": "user", "content": e.user},
                        {"role": "assistant", "content": json.dumps(e.target, ensure_ascii=False)},
                    ],
                    "meta": e.meta,
                },
                ensure_ascii=False,
            )
        )
    return "\n".join(lines)


FORMATS = {"generic": to_jsonl_generic, "messages": to_jsonl_messages}
