"""CLI tests using the offline echo backend."""

import json

from offsec_one.cli import main


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def test_assess_json_output(tmp_path, capsys):
    finding = _write(tmp_path, "f.json", {
        "target": "app.example.com", "topic": "web", "title": "t",
        "state": {"response_headers": {"Server": "x"}},
    })
    rc = main(["assess", finding, "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["finding"]["target"] == "app.example.com"
    assert any("missing-header" in s for s in out["signals"])
    assert "disposition" in out


def test_assess_scope_refused(tmp_path, capsys):
    finding = _write(tmp_path, "f.json", {"target": "evil.other.com", "topic": "web", "title": "t"})
    scope = _write(tmp_path, "s.json", {
        "engagement_id": "E", "authorization_ref": "R", "targets": ["*.example.com"],
    })
    rc = main(["assess", finding, "--scope", scope])
    assert rc == 2
    assert "scope refused" in capsys.readouterr().err


def test_topics_lists_implemented_and_proposed(capsys):
    rc = main(["topics"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "web" in out and "mobile" in out


def test_no_command_prints_help(capsys):
    rc = main([])
    assert rc == 1
