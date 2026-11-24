合并权限策略时靠人眼看等价，结果合并后多了三条没人发现的放行规则：归一化只小写动作不展开资源通配，同一子树被当成两个资源；条件键不排序，同义条件因书写顺序不同被判不等；覆盖判定只看资源不看条件，条件更宽的规则被误判为被覆盖；覆盖判定按字符串前缀比较资源，路径段边界被忽略；包含判定找到第一条覆盖者就返回，重复资源下后续规则漏判；等价判定只做单向包含，A 含 B 就判等价；最小化按出现顺序删除而不检查覆盖者是否仍保留，策略语义被改；最小化把动作相反的冲突项当冗余删掉，放行规则被静默丢弃；冲突检测只比较资源不比较条件，不同条件下的相反动作被误报；批量比较复用归一化结果，第二对策略沿用第一对的条件集合。pol/equiv.py 是核心，tests/test_equiv.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式
--------

在仓库根目录执行：

    python -m pytest tests -q

初始状态必须恰好是 15 failed，不能出现 collection error、import error 或 syntax error；实现 8 个桩后应为 15 passed。测试完全离线，不访问网络，不使用随机数，也不读取系统时间。

字段表
------

字段表：安全 / 漏洞检测与攻防 / Bugfix / Python 3, pytest / 无外部依赖

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

约束
----

tests 目录和 tests/test_equiv.py 不可修改，评测以此文件为准。只能修改 src/pol/equiv.py。

src/pol/equiv.py 是唯一实现文件，恰好 8 个桩，初始全部 raise NotImplementedError。8 个函数依次为 normalize_rule、rule_covers、subsumes、equivalent、minimize、conflicts、merge、policy_batch。实现只使用 Python 标准库，不读取系统时间，不使用随机数。

src 布局与 pyproject
--------------------

    sec-policy-equivalence/
      README.md
      pyproject.toml
      src/
        pol/
          __init__.py
          equiv.py
      tests/
        test_equiv.py

pyproject.toml 的 tool.pytest.ini_options 设置 pythonpath 为 src，测试直接导入 pol.equiv，因此不需要 conftest.py。项目采用 src 布局，包位于 src/pol，测试位于 tests，二者分开。

pyproject.toml 同时声明项目无运行时依赖；pytest 只用于运行测试。测试文件不创建临时文件、不访问网络、不使用随机数，所有输入均为固定值。

测试与缺陷对应
--------------

前 10 个测试分别对应题面的 10 个缺陷，后 5 个覆盖正确语义。

| 测试 | 覆盖点 |
| --- | --- |
| test_defect_01_normalize_expands_wildcard | 动作小写，星号后缀展开为同一子树资源 |
| test_defect_02_condition_keys_are_sorted | 条件键排序，同义条件判等 |
| test_defect_03_rule_coverage_checks_conditions | 覆盖判定必须比较条件子集 |
| test_defect_04_resource_coverage_respects_path_boundary | 资源前缀必须按路径段边界判断 |
| test_defect_05_subsumption_checks_every_rule | 策略包含要逐条检查，不能首条命中即返回 |
| test_defect_06_equivalence_requires_both_directions | 等价必须双向包含 |
| test_defect_07_minimize_preserves_semantics | 最小化不能改变覆盖语义 |
| test_defect_08_minimize_keeps_opposite_actions | 最小化不能删除动作相反的冲突项 |
| test_defect_09_conflicts_compare_conditions | 冲突检测必须同时比较资源与条件 |
| test_defect_10_batch_is_independent | 批量比较的各对策略互相独立 |
| test_identical_policies_are_equivalent | 相同策略等价 |
| test_broader_resource_covers_narrower_not_reverse | 更宽资源覆盖更窄资源，反向不成立 |
| test_minimize_reduces_count_and_preserves_semantics | 最小化减少规则数且保持语义 |
| test_conflict_entries_are_detected | 冲突条目被正确识别，合并保留双方 |
| test_two_batches_match_individual_comparisons | 两对独立比较与单独比较一致 |