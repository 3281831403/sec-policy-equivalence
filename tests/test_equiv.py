"""sec-policy-equivalence 的 15 个行为测试。

全部使用固定输入：不联网、不使用随机数、不读取系统时间。
前 10 个测试分别对应题面中的 10 个缺陷，后 5 个覆盖正确语义。
"""

from pol.equiv import (
    conflicts,
    equivalent,
    merge,
    minimize,
    normalize_rule,
    policy_batch,
    rule_covers,
    subsumes,
)


def test_defect_01_normalize_expands_wildcard():
    left = {"action": "ALLOW", "resource": "/svc/**", "conditions": {}}
    right = {"action": "allow", "resource": "/svc/*", "conditions": {}}

    normalized_left = normalize_rule(left)
    normalized_right = normalize_rule(right)

    assert normalized_left["action"] == "allow"
    assert normalized_left["resource"] == "/svc/"
    assert normalized_left == normalized_right


def test_defect_02_condition_keys_are_sorted():
    left = {
        "action": "allow",
        "resource": "/svc/api",
        "conditions": {"level": "3", "dept": "eng"},
    }
    right = {
        "action": "allow",
        "resource": "/svc/api",
        "conditions": {"dept": "eng", "level": "3"},
    }

    normalized_left = normalize_rule(left)
    normalized_right = normalize_rule(right)

    assert list(normalized_left["conditions"]) == ["dept", "level"]
    assert normalized_left == normalized_right
    assert rule_covers(normalized_left, normalized_right) is True
    assert rule_covers(normalized_right, normalized_left) is True


def test_defect_03_rule_coverage_checks_conditions():
    narrow = {
        "action": "allow",
        "resource": "/svc/api",
        "conditions": {"dept": "eng", "level": "3"},
    }
    wide = {
        "action": "allow",
        "resource": "/svc/api",
        "conditions": {"dept": "eng"},
    }

    assert rule_covers(narrow, wide) is False
    assert rule_covers(wide, narrow) is True


def test_defect_04_resource_coverage_respects_path_boundary():
    exact = {"action": "allow", "resource": "/svc", "conditions": {}}
    scope = {"action": "allow", "resource": "/svc/", "conditions": {}}

    assert rule_covers(exact, {"action": "allow", "resource": "/svc", "conditions": {}}) is True
    assert rule_covers(exact, {"action": "allow", "resource": "/svc/api", "conditions": {}}) is False
    assert rule_covers(scope, {"action": "allow", "resource": "/svc", "conditions": {}}) is True
    assert rule_covers(scope, {"action": "allow", "resource": "/svc/api", "conditions": {}}) is True
    assert rule_covers(scope, {"action": "allow", "resource": "/svc2/api", "conditions": {}}) is False


def test_defect_05_subsumption_checks_every_rule():
    base = [
        {"action": "allow", "resource": "/svc/api", "conditions": {"dept": "eng"}},
        {"action": "allow", "resource": "/svc/api", "conditions": {"dept": "ops"}},
    ]
    extra = base + [
        {"action": "allow", "resource": "/svc/api", "conditions": {"dept": "fin"}}
    ]

    assert subsumes(extra, base) is True
    assert subsumes(base, extra) is False


def test_defect_06_equivalence_requires_both_directions():
    broad = [{"action": "allow", "resource": "/svc/", "conditions": {}}]
    narrow = [{"action": "allow", "resource": "/svc/api", "conditions": {}}]

    assert subsumes(broad, narrow) is True
    assert subsumes(narrow, broad) is False
    assert equivalent(broad, narrow) is False


def test_defect_07_minimize_preserves_semantics():
    policy = [
        {"action": "allow", "resource": "/svc/", "conditions": {"dept": "eng"}},
        {"action": "allow", "resource": "/svc/api", "conditions": {"dept": "eng"}},
        {
            "action": "allow",
            "resource": "/svc/api",
            "conditions": {"dept": "eng", "level": "3"},
        },
        {"action": "ALLOW", "resource": "/svc/**", "conditions": {"dept": "eng"}},
    ]

    minimized = minimize(policy)

    assert len(minimized) == 1
    assert subsumes(minimized, policy) is True
    assert subsumes(policy, minimized) is True
    assert equivalent(minimized, policy) is True


def test_defect_08_minimize_keeps_opposite_actions():
    policy = [
        {"action": "allow", "resource": "/svc/api", "conditions": {"dept": "eng"}},
        {"action": "deny", "resource": "/svc/api", "conditions": {"dept": "eng"}},
        {
            "action": "allow",
            "resource": "/svc/api",
            "conditions": {"dept": "eng", "level": "3"},
        },
    ]

    minimized = minimize(policy)

    assert len(minimized) == 2
    assert sorted(rule["action"] for rule in minimized) == ["allow", "deny"]

    pairs = conflicts(minimized)
    assert len(pairs) == 1
    allow_rule, deny_rule = pairs[0]
    assert allow_rule["action"] == "allow"
    assert deny_rule["action"] == "deny"
    assert allow_rule["resource"] == "/svc/api"
    assert deny_rule["resource"] == "/svc/api"
    assert allow_rule["conditions"] == {"dept": "eng"}
    assert deny_rule["conditions"] == {"dept": "eng"}


def test_defect_09_conflicts_compare_conditions():
    policy = [
        {"action": "allow", "resource": "/svc/api", "conditions": {"dept": "eng"}},
        {"action": "deny", "resource": "/svc/api", "conditions": {"dept": "ops"}},
    ]

    assert conflicts(policy) == []


def test_defect_10_batch_is_independent():
    reference = [
        {"action": "allow", "resource": "/svc/", "conditions": {"dept": "eng"}}
    ]
    first = [
        {"action": "allow", "resource": "/svc/", "conditions": {"dept": "ops"}}
    ]
    second = [
        {"action": "allow", "resource": "/svc/", "conditions": {"dept": "eng"}}
    ]

    batch = policy_batch([("first", first), ("second", second)], reference)

    assert batch["first"] == {"equivalent": False, "subsumes": False}
    assert batch["second"] == {"equivalent": True, "subsumes": True}


def test_identical_policies_are_equivalent():
    first = [
        {"action": "allow", "resource": "/svc/", "conditions": {"dept": "eng", "level": "3"}},
        {"action": "deny", "resource": "/svc/api", "conditions": {"dept": "ops"}},
    ]
    second = [
        {"action": "deny", "resource": "/svc/api", "conditions": {"dept": "ops"}},
        {"action": "ALLOW", "resource": "/svc/**", "conditions": {"level": "3", "dept": "eng"}},
    ]

    assert equivalent(first, second) is True
    assert equivalent(second, first) is True


def test_broader_resource_covers_narrower_not_reverse():
    broad = [
        {"action": "allow", "resource": "/svc/", "conditions": {"dept": "eng"}}
    ]
    narrow = [
        {
            "action": "allow",
            "resource": "/svc/api",
            "conditions": {"dept": "eng", "level": "3"},
        }
    ]

    assert subsumes(broad, narrow) is True
    assert subsumes(narrow, broad) is False
    assert equivalent(broad, narrow) is False


def test_minimize_reduces_count_and_preserves_semantics():
    policy = [
        {"action": "allow", "resource": "/svc/", "conditions": {}},
        {"action": "allow", "resource": "/svc/api", "conditions": {}},
        {
            "action": "allow",
            "resource": "/svc/api",
            "conditions": {"level": "3"},
        },
        {"action": "deny", "resource": "/svc/api", "conditions": {"dept": "ops"}},
    ]

    minimized = minimize(policy)

    assert len(minimized) == 2
    assert len(minimized) < len(policy)
    assert subsumes(minimized, policy) is True
    assert subsumes(policy, minimized) is True
    assert equivalent(minimized, policy) is True


def test_conflict_entries_are_detected():
    allow_rule = {
        "action": "ALLOW",
        "resource": "/svc/**",
        "conditions": {"level": "3", "dept": "eng"},
    }
    deny_rule = {
        "action": "deny",
        "resource": "/svc/*",
        "conditions": {"dept": "eng", "level": "3"},
    }

    merged = merge([allow_rule, allow_rule], [deny_rule, deny_rule])
    assert len(merged) == 2

    pairs = conflicts(merged)
    assert len(pairs) == 1

    allow_out, deny_out = pairs[0]
    assert allow_out == {
        "action": "allow",
        "resource": "/svc/",
        "conditions": {"dept": "eng", "level": "3"},
    }
    assert deny_out == {
        "action": "deny",
        "resource": "/svc/",
        "conditions": {"dept": "eng", "level": "3"},
    }


def test_two_batches_match_individual_comparisons():
    reference = [
        {"action": "allow", "resource": "/svc/", "conditions": {"dept": "eng"}}
    ]
    pairs = [
        (
            "same",
            [{"action": "allow", "resource": "/svc/**", "conditions": {"dept": "eng"}}],
        ),
        (
            "narrow",
            [{"action": "allow", "resource": "/svc/api", "conditions": {"dept": "eng"}}],
        ),
    ]

    batch = policy_batch(pairs, reference)

    assert batch["same"] == {"equivalent": True, "subsumes": True}
    assert batch["narrow"] == {"equivalent": False, "subsumes": False}
    for label, candidate in pairs:
        assert batch[label]["equivalent"] == equivalent(candidate, reference)
        assert batch[label]["subsumes"] == subsumes(candidate, reference)