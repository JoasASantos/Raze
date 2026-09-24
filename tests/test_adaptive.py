"""Adaptive attack-path scoring tests — signal accumulation + live state."""

from raze.adaptive import AdaptiveEngagement, AdaptiveScorer, LiveState, Strategy


def _s(id, vc, prereqs=None, yields=None, chain=False):
    return Strategy(id=id, finding_title=id, description=id, vuln_class=vc,
                    prerequisites=prereqs or [], yields=yields or [], advances_chain=chain)


def test_unmet_prereqs_are_discounted():
    scorer = AdaptiveScorer()
    live = LiveState()
    s = _s("privesc", "dcsync", prereqs=["domain_user"])
    scored = scorer.score(s, live)
    assert not scored.runnable
    assert scored.factors["runnable_mult"] == 0.25
    # Discover the prereq -> becomes runnable and scores higher.
    live.discovered.add("domain_user")
    scored2 = scorer.score(s, live)
    assert scored2.runnable and scored2.score > scored.score


def test_signal_accumulates_and_shifts_attention():
    eng = AdaptiveEngagement()
    sqli = _s("sqli-1", "sqli")
    xss = _s("xss-1", "xss_reflected")
    before = {x.strategy.id: x.score for x in eng.rank([sqli, xss])}
    # A sqli strategy lands -> reinforce the sqli class.
    eng.report_result(sqli, success=True)
    after = {x.strategy.id: x.score for x in eng.rank([sqli, xss])}
    assert after["sqli-1"] > before["sqli-1"]  # signal boosted
    assert after["xss-1"] == before["xss-1"]  # other class unchanged


def test_failure_penalizes():
    eng = AdaptiveEngagement()
    s = _s("try", "sqli")
    base = eng.rank([s])[0].score
    eng.report_result(s, success=False)
    assert eng.rank([s])[0].score < base


def test_success_yields_unlock_dependents():
    eng = AdaptiveEngagement()
    foothold = _s("foothold", "unauth_service", yields=["shell"])
    pivot = _s("pivot", "dcsync", prereqs=["shell"])
    assert not eng.scorer.score(pivot, eng.live).runnable
    eng.report_result(foothold, success=True)
    assert eng.scorer.score(pivot, eng.live).runnable


def test_next_best_prefers_runnable_high_score():
    eng = AdaptiveEngagement()
    blocked = _s("blocked", "dcsync", prereqs=["da"])  # high base but not runnable
    ready = _s("ready", "sqli")  # runnable
    assert eng.next_best([blocked, ready]).strategy.id == "ready"


def test_chain_advance_bonus():
    scorer = AdaptiveScorer()
    live = LiveState()
    plain = scorer.score(_s("a", "sqli"), live).score
    chained = scorer.score(_s("b", "sqli", chain=True), live).score
    assert chained > plain
