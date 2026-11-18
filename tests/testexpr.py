import pytest

from inspector import expr

V = {"cpu.percent": 95.0, "mem.percent": 40.0, "up": 1.0, "disk./.percent": 50.0,
     "disk./data.percent": 91.0, "disk./data.inode_percent": 3.0, "service.nginx.up": 0.0,
     "service.crond.up": 1.0, "check.ntp": "no"}


@pytest.mark.parametrize("text, expected", [
    ("cpu.percent > 90", True),
    ("cpu.percent > 90 and mem.percent > 90", False),
    ("cpu.percent > 90 or mem.percent > 90", True),
    ("not (cpu.percent > 90)", False),
    ("up == 1", True),
    ("cpu.percent >= 95", True),
    ("cpu.percent != 95", False),
    ('check.ntp == "no"', True),
    ("check.ntp == 'yes'", False),
    ("mem.percent < 50 and (up == 0 or cpu.percent > 90)", True),
])
def test_evaluate(text, expected):
    assert expr.evaluate(expr.parse(text), V) is expected


def test_missing_metric_is_no_data_not_false():
    node = expr.parse("swap.percent > 50")
    assert expr.evaluate(node, V) is None


def test_no_data_propagates_through_and_or():
    assert expr.evaluate(expr.parse("cpu.percent > 90 and swap.percent > 50"), V) is None
    assert expr.evaluate(expr.parse("cpu.percent > 90 or swap.percent > 50"), V) is None


def test_ordering_text_against_number_is_no_data():
    assert expr.evaluate(expr.parse("check.ntp > 3"), V) is None


def test_wildcards_bind_one_target():
    node = expr.parse("disk.*.percent > 85 and disk.*.percent <= 95")
    assert expr.wildcard_targets(node, V.keys()) == {"/", "/data"}
    assert expr.evaluate(node, V, "/data") is True
    assert expr.evaluate(node, V, "/") is False


def test_wildcard_does_not_match_inode_keys():
    node = expr.parse("disk.*.percent > 0")
    assert "/data.inode" not in expr.wildcard_targets(node, V.keys())


def test_service_wildcard():
    node = expr.parse("service.*.up == 0")
    assert expr.wildcard_targets(node, V.keys()) == {"nginx", "crond"}
    assert expr.evaluate(node, V, "nginx") is True


def test_keys_in_order():
    assert expr.keys(expr.parse("b.x > 1 and a.y < 2 or b.x == 3")) == ["b.x", "a.y"]


@pytest.mark.parametrize("bad", [
    "", "cpu.percent >", "cpu.percent", "> 90", "cpu.percent > 90 and",
    "(cpu.percent > 90", "cpu.percent > 90)", "__import__('os').system('id')",
    "cpu.percent > 90; rm -rf /", "cpu.percent = 90",
])
def test_invalid_expressions_rejected(bad):
    with pytest.raises(expr.ExprError):
        expr.parse(bad)
