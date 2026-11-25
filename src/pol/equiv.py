"""权限策略等价、覆盖、最小化与冲突判定的唯一实现文件。

数据模型
--------
策略是规则列表。规则是映射，至少包含下列键：
    action: "allow" 或 "deny"，大小写不敏感
    resource: 以斜杠开头的资源路径
    conditions: 可选映射，键和值均为标量；缺失或 None 视为空映射

资源作用域
----------
规范化后的资源只有两种形式：
    /svc/api     精确资源
    /svc/        子树作用域，覆盖 /svc 本身以及 /svc/ 下的任意深度资源
    /            根作用域，覆盖全部资源

输入中的结尾星号段 /* 与 /** 是子树通配后缀，分别规范化为去掉星号后的
尾斜杠形式。例如 /svc/* 与 /svc/** 都规范化为 /svc/。根通配 * 或 **
规范化为 /。连续斜杠折叠为一个，缺少前导斜杠时补上。资源大小写敏感。

条件语义
--------
规则 a 的条件是规则 b 的条件子集时，a 的适用范围不窄于 b。覆盖只允许
条件更少或相等，不能丢掉 b 已有的限制。

动作与容差
----------
覆盖要求动作完全相同；allow 不覆盖 deny。所有比较容差为 0：不做字符串
前缀、大小写折叠（动作除外）、模糊匹配或路径别名解析。
"""

import re
from collections.abc import Mapping


def _normalize_resource(raw) -> str:
    """资源路径规范化：折叠斜杠、补前导斜杠、展开结尾通配段。

    星号只允许作为最后一个路径段且整段恰为 * 或 **，否则 ValueError。
    """
    if not isinstance(raw, str):
        raise ValueError("resource must be a string")
    text = re.sub(r"/+", "/", raw)
    if not text.startswith("/"):
        text = "/" + text

    ends_with_slash = text.endswith("/")
    body = text[1:-1] if ends_with_slash else text[1:]
    segments = body.split("/") if body else []

    for index, segment in enumerate(segments):
        if "*" in segment and (
            index != len(segments) - 1 or segment not in ("*", "**")
        ):
            raise ValueError(
                "wildcard is only allowed as the final * or ** segment"
            )

    if segments and segments[-1] in ("*", "**"):
        # 子树通配：丢掉星号段，统一成尾斜杠形式；根通配规范为 /。
        segments = segments[:-1]
        return "/" + "/".join(segments) + "/" if segments else "/"

    if ends_with_slash:
        return "/" + "/".join(segments) + "/" if segments else "/"
    return "/" + "/".join(segments) if segments else "/"


def _resource_parts(resource: str):
    """返回 (路径段元组, 是否子树作用域)。"""
    is_subtree = resource.endswith("/")
    body = resource[1:-1] if is_subtree else resource[1:]
    segments = tuple(body.split("/")) if body else ()
    return segments, is_subtree


def _resource_covers(resource_a: str, resource_b: str) -> bool:
    """按路径段边界判断 a 的资源作用域是否包含 b 的资源作用域。"""
    segments_a, subtree_a = _resource_parts(resource_a)
    segments_b, _subtree_b = _resource_parts(resource_b)
    if not subtree_a:
        # 精确资源只覆盖同样精确且路径段完全相等的资源。
        return not _subtree_b and segments_a == segments_b
    # 子树作用域：b 的路径段必须以 a 的路径段为整段前缀。
    return segments_b[: len(segments_a)] == segments_a


def normalize_rule(rule: dict) -> dict:
    """返回规范化规则。

    action 去空白并小写，只接受 allow 或 deny，否则抛出 ValueError。
    resource 按模块说明折叠斜杠、补前导斜杠、把结尾的 /* 或 /** 展开为
    尾斜杠子树形式；根通配规范为 /。星号只允许作为最后一个路径段，否则
    抛出 ValueError。conditions 接受映射，返回按键字典序排序的新字典；
    缺失或 None 视为空字典。返回值恰好包含 action、resource、conditions
    三个键，丢弃未知键。
    """
    raw_action = rule.get("action")
    if not isinstance(raw_action, str):
        raise ValueError("action must be a string")
    action = raw_action.strip().lower()
    if action not in ("allow", "deny"):
        raise ValueError("invalid action: %r" % (raw_action,))

    resource = _normalize_resource(rule.get("resource"))

    raw_conditions = rule.get("conditions")
    if raw_conditions is None:
        conditions = {}
    elif isinstance(raw_conditions, Mapping):
        conditions = dict(sorted(raw_conditions.items()))
    else:
        raise ValueError("conditions must be a mapping")

    return {"action": action, "resource": resource, "conditions": conditions}


def rule_covers(a: dict, b: dict) -> bool:
    """判断规则 a 是否覆盖规则 b。

    两个参数都先 normalize_rule。覆盖成立当且仅当：
    1. 动作相同；
    2. a 的资源作用域包含 b 的资源作用域；
    3. a 的条件键值全部出现在 b 的条件中，即 a 的条件是 b 的子集。

    资源覆盖按路径段判断。子树 /svc/ 覆盖 /svc、/svc/ 以及 /svc/ 下的
    任意路径；精确 /svc 只覆盖 /svc；/svc/ 不覆盖 /svc2 或 /svc2/ 下的
    路径。条件更多、限制更窄的规则不覆盖条件更少的规则。返回 bool。
    """
    na = normalize_rule(a)
    nb = normalize_rule(b)

    if na["action"] != nb["action"]:
        return False
    if not _resource_covers(na["resource"], nb["resource"]):
        return False

    conditions_a = na["conditions"]
    conditions_b = nb["conditions"]
    return all(
        key in conditions_b and conditions_b[key] == value
        for key, value in conditions_a.items()
    )


def subsumes(policy_a: list, policy_b: list) -> bool:
    """判断策略 a 是否包含策略 b。

    逐条检查 b 的每条规则，必须能在 a 中找到至少一条覆盖它的规则。
    不能找到第一条就返回：b 中后续规则也必须逐条检查。空 b 返回 True；
    a 为空且 b 非空返回 False。两侧都先规范化，重复规则不影响结果。
    """
    normalized_a = [normalize_rule(rule) for rule in policy_a]
    normalized_b = [normalize_rule(rule) for rule in policy_b]

    for rule_b in normalized_b:
        if not any(rule_covers(rule_a, rule_b) for rule_a in normalized_a):
            return False
    return True


def equivalent(policy_a: list, policy_b: list) -> bool:
    """判断两个策略是否语义等价。

    等价要求 subsumes(policy_a, policy_b) 与 subsumes(policy_b, policy_a)
    同时成立，不能只做单向包含。两侧都先规范化。
    """
    return subsumes(policy_a, policy_b) and subsumes(policy_b, policy_a)


def _rule_key(rule: dict):
    return (
        rule["action"],
        rule["resource"],
        tuple(rule["conditions"].items()),
    )


def minimize(policy: list) -> list:
    """返回去冗余后的策略。

    输入规则先规范化，完全相同的规则只保留第一次出现。对同动作规则，
    若一条规则被另一条同动作规则覆盖，则可删除；但动作相反的冲突项
    （同资源、同条件、动作一 allow 一 deny）必须保留，不能静默丢弃。
    结果保持存活规则在输入中的相对顺序，并保证与输入策略双向包含。
    """
    # 先规范化并按首次出现去重。
    rules = []
    seen = set()
    for rule in policy:
        normalized = normalize_rule(rule)
        key = _rule_key(normalized)
        if key not in seen:
            seen.add(key)
            rules.append(normalized)

    # 覆盖关系具有传递性：任何被覆盖的规则沿覆盖链向上都会到达一个
    # 不被任何规则覆盖的极大规则，而极大规则一定存活。因此只需判断
    # 是否存在另一条“同动作”覆盖者；动作相反的规则永远不构成覆盖，
    # 冲突项自然保留。
    alive = [True] * len(rules)
    for index, rule in enumerate(rules):
        for other_index, other in enumerate(rules):
            if other_index == index:
                continue
            if other["action"] != rule["action"]:
                continue
            if rule_covers(other, rule):
                alive[index] = False
                break

    return [rule for index, rule in enumerate(rules) if alive[index]]


def conflicts(policy: list) -> list:
    """返回策略内的动作冲突对。

    规则先规范化。冲突对由一条 allow 和一条 deny 组成，二者的规范化资源
    完全相等且条件映射完全相等；只比较资源不比较条件是错误的，条件不同
    不算冲突。返回列表，元素为 (allow_rule, deny_rule) 二元组，组内 allow
    在前；按 allow 在输入中的顺序、再按 deny 顺序排列。完全相同的冲突对
    只返回一次。无冲突返回空列表。
    """
    rules = [normalize_rule(rule) for rule in policy]
    allow_rules = [rule for rule in rules if rule["action"] == "allow"]
    deny_rules = [rule for rule in rules if rule["action"] == "deny"]

    pairs = []
    seen = set()
    for allow_rule in allow_rules:
        for deny_rule in deny_rules:
            if (
                allow_rule["resource"] == deny_rule["resource"]
                and allow_rule["conditions"] == deny_rule["conditions"]
            ):
                key = (
                    allow_rule["resource"],
                    tuple(allow_rule["conditions"].items()),
                )
                if key not in seen:
                    seen.add(key)
                    pairs.append((allow_rule, deny_rule))
    return pairs


def merge(policy_a: list, policy_b: list) -> list:
    """合并两个策略并去重，冲突条目保留两者。

    两侧规则先规范化，按 a 再 b 的顺序输出。动作、资源、条件三者都相同
    的规则只保留第一次出现；动作相反的同资源同条件规则不是重复，必须
    都保留。不改变输入。
    """
    merged = []
    seen = set()
    for rule in list(policy_a) + list(policy_b):
        normalized = normalize_rule(rule)
        key = _rule_key(normalized)
        if key not in seen:
            seen.add(key)
            merged.append(normalized)
    return merged


def policy_batch(pairs: list, policy: list) -> dict:
    """批量比较若干候选策略与同一基准策略，各对独立。

    pairs 是 (label, candidate_policy) 二元组的序列，label 可哈希且不重复；
    policy 是共享的基准策略。对每个候选独立计算：
        subsumes: candidate 是否包含 policy
        equivalent: candidate 与 policy 是否等价
    返回 {label: {"equivalent": bool, "subsumes": bool}}，值恰好包含这两个
    键。一个候选的规范化结果、条件集合或中间状态不得被下一个候选复用。
    """
    result = {}
    for label, candidate in pairs:
        # 所有中间结果都是循环内局部变量，下一个候选从头规范化、独立计算。
        candidate_subsumes = subsumes(candidate, policy)
        candidate_equivalent = candidate_subsumes and subsumes(policy, candidate)
        result[label] = {
            "equivalent": candidate_equivalent,
            "subsumes": candidate_subsumes,
        }
    return result
