# 翼型工程数据库系统 — 实验操作大纲

> 面向实验人员：本大纲覆盖**事务实验、触发器实验、视图实验、存储过程实验**四大部分，
> 与课程项目说明书（七、数据库高级机制要求）及（八、数据治理要求）直接对应。
> 所有实验均通过 Web 界面操作，无需手动编写后端代码。

---

## 前置条件

### 1. 环境启动

```powershell
# 设置 MySQL 连接信息
$env:MYSQL_HOST = "127.0.0.1"
$env:MYSQL_USER = "root"
$env:MYSQL_PASSWORD = "your_password"
$env:MYSQL_DATABASE = "airfoil_engineering_db"
$env:FLASK_HOST = "127.0.0.1"
$env:FLASK_PORT = "5000"

# 启动后端
python backend\app.py
```

### 2. 登录

浏览器打开 `http://127.0.0.1:5000`，使用 **engineer 或 admin** 账号登录。
（viewer 仅能执行 SELECT；事务/触发器/存储过程实验需要 engineer 及以上权限。）

### 3. 实验入口一览

| 标签页 | 对应实验 | 对应说明书章节 |
|--------|---------|---------------|
| **事务实验** | 并发控制、批量回滚、原子性 | 七.2 |
| **数据库对象实验** | 触发器 / 视图 / 存储过程 | 七.3 |
| **索引实验** | 索引创建/删除/EXPLAIN 对比 | 七.1 |

---

## 第一部分：事务实验

> 对应说明书 **七.2（事务或并发实验）**，三个推荐场景全部覆盖。

### 实验前准备

进入「**事务实验**」标签页后，你会看到：

- 上方三个**场景按钮**（一键填充 SQL）
- 中间**事务保存区**（保存/载入/删除常用事务脚本）
- 下方**事务编辑器** + **执行并回滚** / **执行并提交** 按钮

**建议操作顺序**：场景 1 → 场景 2 → 场景 3 → 自由事务。

### 实验人员通用记录要求

每个事务实验至少保留以下材料，方便后续写实验报告：

1. 当前登录用户和角色（建议使用 engineer 或 admin）
2. 点击的场景按钮或手动输入的 SQL
3. 页面返回的事务状态（`committed` / `rolled back` / 错误信息）
4. 验证用 SELECT 的结果
5. 若实验目的是失败回滚，必须截图证明正式表没有残留测试数据

**注意**：事务实验中使用的测试编号（如 `9000001`、`9000002`、`9100001`）是固定演示编号。重复执行时，如果上一次选择了「执行并提交」，可能需要先清理测试记录，或改用「执行并回滚」完成演示。

---

### 场景 1：并发修改同一性能记录

**实验目的**：观察 InnoDB 行级锁机制，理解两个用户同时修改同一条记录时的排队等待行为。

**操作步骤**：

1. 点击 **「场景1：并发修改同一性能记录」** 按钮
2. 等待约 3 秒，观察右侧结果面板

**系统内部行为**（无需手动操作）：

```
User A: BEGIN → UPDATE cl=0.111 WHERE perf_id=9100001 → 持有行锁 2 秒 → COMMIT
User B: 等待 0.3 秒后 BEGIN → UPDATE cl=0.222 WHERE perf_id=9100001 → 等待 User A 释放锁 → COMMIT
```

**预期结果**：

- User A 先获得行锁，耗时 < 10ms
- User B 的 UPDATE 耗时约 2000ms（等待 User A 释放锁）
- 最终 `performance_records` 中 `perf_id=9100001` 的 `cl = 0.222`
- 不会出现死锁错误（锁等待超时设为 8 秒，远大于 User A 的 2 秒持有时间）

**实验记录要点**：

- 截取 Timeline 表格（显示每一步的时间和耗时）
- 记录 User B 等待时间
- 回答：如果 User A 持有锁 10 秒会发生什么？（提示：`innodb_lock_wait_timeout = 8`）

---

### 场景 2：批量导入失败回滚

**实验目的**：验证事务的**原子性（Atomicity）**——批量操作中任一条失败则全部回滚。

**操作步骤**：

1. 点击 **「场景2：批量导入失败回滚」** 按钮
2. 事务编辑器中会填入两条 INSERT 语句 + 一条验证 SELECT：

```sql
INSERT INTO performance_records
(perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
VALUES
(9000001, 'ag03', 1, 0, 123456, 0.5, 0.01, 0.0, 'generated_synthetic', 0);   -- ✅ 合法

INSERT INTO performance_records
(perf_id, airfoil_id, version_id, alpha_deg, reynolds_number, cl, cd, cm, source_type, is_anomaly)
VALUES
(9000002, 'ag03', 1, 99, 123456, 0.6, 0.02, 0.0, 'generated_synthetic', 0);  -- ❌ alpha_deg=99 违反 CHECK(alpha_deg >= -20 AND alpha_deg <= 25)

SELECT perf_id, airfoil_id, alpha_deg, reynolds_number, cl, cd
FROM performance_records
WHERE perf_id IN (9000001, 9000002);
```

3. 点击 **「执行并提交」** 按钮

**预期结果**：

- 第二条 INSERT 因违反 `CHECK (alpha_deg >= -20 AND alpha_deg <= 25)` 而失败
- 事务整体回滚，第一条合法 INSERT 也**不会被写入**
- 最终验证 SELECT 返回 **0 行**
- 状态显示 `rolled back`

**此时建议补充操作**：

4. 删除第二条非法 INSERT，只保留第一条，点击「执行并提交」
5. 观察：这次返回 `committed`，`perf_id=9000001` 写入成功

**实验记录要点**：

- 对比「含非法数据」和「仅合法数据」两次执行的结果
- 说明 MySQL 如何保证"全有或全无"（all-or-nothing）
- 指出违反的具体约束（CHECK `alpha_deg` 范围）

---

### 场景 3：主表与版本表同时失败

**实验目的**：验证**跨表事务一致性**——更新主表和版本表时，任一失败导致全部回滚。

**操作步骤**：

1. 点击 **「场景3：主表与版本表同时失败」** 按钮
2. 编辑器中会填入：

```sql
UPDATE airfoils
SET family = 'Version Atomic Test'
WHERE airfoil_id = 'ag03';                                          -- ✅ 合法

UPDATE data_versions
SET version_type = 'bad_version_type'
WHERE airfoil_id = 'ag03' AND version_id = 1;                       -- ❌ 违反 CHECK(version_type IN ('imported_raw','augmented_from_raw'))

SELECT a.airfoil_id, a.family, v.version_id, v.version_type
FROM airfoils a
JOIN data_versions v ON v.airfoil_id = a.airfoil_id
WHERE a.airfoil_id = 'ag03' AND v.version_id = 1;
```

3. 点击 **「执行并提交」**

**预期结果**：

- 第二条 UPDATE 失败，违反 `CHECK (version_type IN ('imported_raw','augmented_from_raw'))`
- 事务回滚，`airfoils.family` **保持原值不变**
- 验证 SELECT 显示的 family 仍为原始值（如 `"AG"` 或原有值）

**实验记录要点**：

- 用此场景说明"为什么版本相关操作必须放在同一事务中"
- 指出：如果无事务保护，第一条 UPDATE 成功而第二条失败 → 数据不一致

---

### 自由事务实验（手动模式）

**实验目的**：实验人员自己编写事务 SQL，验证 COMMIT / ROLLBACK 行为。

**操作建议**：

1. 在事务编辑器中写入自定义 SQL（允许多条 SELECT/INSERT/UPDATE/DELETE）
2. 点击 **「执行并回滚」**：观察所有修改被撤销
3. 再次点击 **「执行并提交」**：观察修改持久化

**推荐测试用例**：

```sql
-- 测试 1：回滚验证
UPDATE airfoils SET family = 'ROLLBACK_TEST' WHERE airfoil_id = 'ag03';
SELECT airfoil_id, family FROM airfoils WHERE airfoil_id = 'ag03';
-- 点击"执行并回滚"，再去翼型总览页确认 family 未变

-- 测试 2：提交验证
UPDATE airfoils SET family = 'COMMIT_TEST' WHERE airfoil_id = 'ag03';
-- 点击"执行并提交"，确认 family 已改变
-- 手动改回原值
```

**保存常用事务**：在「transaction title」输入框填写名称后点击「保存当前事务」，下次可通过下拉框载入。

**多用户说明**：保存的事务脚本按当前登录用户隔离。A 用户保存的事务不会出现在 B 用户的下拉框中，适合每个实验人员保存自己的测试脚本。

---

## 第二部分：触发器实验

> 对应说明书 **七.3（视图、触发器或存储过程）**。

系统注册了 3 个触发器：

| 触发器 | 触发时机 | 功能 |
|--------|---------|------|
| `trg_anomaly_requires_flag_insert` | BEFORE INSERT ON anomaly_records | 拒绝引用 `is_anomaly=0` 的性能记录 |
| `trg_anomaly_requires_flag_update` | BEFORE UPDATE ON anomaly_records | 同上，更新时也检查 |
| `trg_audit_performance_update` | AFTER UPDATE ON performance_records | 自动将新旧值写入 audit_logs |

### 实验入口

进入「**数据库对象实验**」标签页。

---

### 实验 A：触发器拒绝非法异常记录

**实验目的**：验证触发器能阻止引用正常性能记录的异常标记。

**操作步骤**：

1. 点击 **「触发器拒绝非法异常」** 按钮
2. 观察结果面板

**系统内部行为**：

```
Step 1: INSERT INTO performance_records (perf_id=9200001, is_anomaly=0)   -- 正常性能记录
Step 2: INSERT INTO anomaly_records (anomaly_id=9920001, perf_id=9200001) -- 尝试引用 is_anomaly=0 的记录
Step 3: 触发器检查 → SIGNAL SQLSTATE '45000' → 拒绝插入
```

**预期结果**：

- 状态显示 `rejected`
- 错误信息包含：`AnomalyRecord must reference a PerformanceRecord with is_anomaly = 1`
- 引用的 performance record 确认 `is_anomaly = 0`

**实验记录要点**：

- 说明触发器在此处的作用：**在数据库层面保证跨表数据一致性**
- 对比"应用层校验"与"触发器校验"的优劣：触发器不能被应用层绕过

---

### 实验 B：触发器自动审计

**实验目的**：验证 UPDATE 触发器自动记录变更前后的值到 `audit_logs`。

**操作步骤**：

1. 点击 **「触发器自动审计」** 按钮
2. 观察结果面板的审计日志

**系统内部行为**：

```
Step 1: 确保 perf_id=9200001 存在 (cl=0.100)
Step 2: UPDATE performance_records SET cl = cl + 0.002 WHERE perf_id = 9200001
Step 3: 触发器自动写入 audit_logs (old: cl=0.100 → new: cl=0.102)
```

**预期结果**：

- Updated record 显示 `cl = 0.102`
- audit_logs 中出现一条新记录，`operation_type = 'UPDATE'`
- `old_values` 包含 `{"cl": 0.100, ...}`，`new_values` 包含 `{"cl": 0.102, ...}`

**实验记录要点**：

- 注意 `old_values` 和 `new_values` 的 JSON 内容
- 说明这种审计机制在生产环境中的价值：**所有数据修改可追溯**

**补充验证操作**（可选）：

多次点击「触发器自动审计」按钮，观察 `audit_logs` 中记录逐次增多。实验重点是证明每一次 UPDATE 都会产生独立审计记录，而不是只看某个数值是否持续累加。
每条审计记录都应能看到 `table_name`、`operation_type`、`record_pk`、`old_values`、`new_values`、`created_at` 等字段。

### 触发器实验截图要求

1. 截图触发器拒绝非法异常时的 `rejected` 状态和错误信息
2. 截图被引用的 `performance_records.is_anomaly = 0`
3. 截图自动审计实验中的 Updated record
4. 截图 `audit_logs` 新增记录，重点圈出 old/new JSON 字段
5. 报告中说明：触发器是在数据库层生效，即使绕过前端直接写 SQL，也会被数据库检查

---

## 第三部分：视图实验

> 对应说明书 **七.3**。

系统注册了 3 个视图：

| 视图 | 功能 |
|------|------|
| `v_airfoil_overview` | 每个翼型的版本数/坐标数/性能数/异常数汇总 |
| `v_performance_with_ld` | 在 performance_records 基础上增加升阻比派生列 |
| `v_anomaly_details` | 异常记录 + 性能值 + 翼型名称的联合视图 |

### 实验入口

进入「**数据库对象实验**」标签页，点击 **「视图查询」**。

**数据库层验证**（可选，用于报告截图）：

```sql
SHOW FULL TABLES WHERE Table_type = 'VIEW';
SHOW CREATE VIEW v_airfoil_overview;
SHOW CREATE VIEW v_performance_with_ld;
SHOW CREATE VIEW v_anomaly_details;
```

这些命令用于证明本实验使用的是数据库对象 `CREATE VIEW`，不是前端临时拼接的普通查询。

---

### 三个视图的观察要点

**1. v_airfoil_overview**

- 展示每个翼型的数据完整度快照
- 注意 `anomaly_count` 列：异常越多的翼型排在最前面
- 实验问题：哪些翼型异常数最高？手动去该翼型页面验证。

**2. v_performance_with_ld**

- 固定 Re=50000，按 `lift_drag_ratio` 降序排列
- 关键列 `lift_drag_ratio = cl / cd`（cd=0 时返回 NULL）
- 实验问题：升阻比最高的翼型是什么？该翼型的 CL 和 CD 大约是多少？

**3. v_anomaly_details**

- 每条异常记录被展开为完整信息：哪个翼型、什么攻角、什么规则触发
- 实验问题：`negative_cd` 类型的异常记录有多少条？它们的 CD 值是多少？

**实验记录要点**：

- 对比「直接 JOIN 查询」与「使用视图查询」的 SQL 复杂度差异
- 说明视图在简化查询和封装业务逻辑方面的价值
- 思考：如果 `lift_drag_ratio` 不通过视图而由应用层计算，会有什么问题？

**视图实验截图要求**：

1. 截图 `v_airfoil_overview` 的汇总结果，体现版本数、坐标点数、性能记录数、异常数
2. 截图 `v_performance_with_ld` 的升阻比排序结果，体现 `lift_drag_ratio = cl / cd`
3. 截图 `v_anomaly_details` 的异常展开结果，体现异常记录可以追溯到翼型、版本和性能值
4. 如果使用 MySQL 命令行验证，补充 `SHOW FULL TABLES WHERE Table_type = 'VIEW'` 或 `SHOW CREATE VIEW` 截图

---

## 第四部分：存储过程实验

> 对应说明书 **七.3**。

系统注册了 4 个存储过程：

| 存储过程 | 功能 | 对应按钮 |
|---------|------|---------|
| `sp_airfoil_performance_summary` | 汇总一个翼型版本按 Re 分组的性能统计 | 存储过程统计分析 |
| `sp_compare_airfoils_by_re` | 在同一 Re 下按选定指标排名翼型 | 存储过程统计分析 |
| `sp_validate_performance_import_batch` | 验证暂存表中的批量数据 | （被 sp_import 内部调用） |
| `sp_import_performance_batch` | 全有或全无的批量导入 | 非法/合法批量导入 |

---

### 实验 A：存储过程统计分析

**实验目的**：体验存储过程封装复杂聚合查询的能力。

**操作步骤**：

1. 点击 **「存储过程统计分析」** 按钮
2. 观察两个结果表

**结果 1：`CALL sp_airfoil_performance_summary('ag03', 1)`**

- 按雷诺数分组展示 ag03 翼型版本 1 的性能汇总
- 包含：样本数、最小 CD、最大 CL、平均 CL、最大升阻比、异常数
- 每个雷诺数一行
- 该过程体现：把固定翼型、固定版本下的统计分析封装成可复用数据库过程

**结果 2：`CALL sp_compare_airfoils_by_re(50000, 'max_ld', 10)`**

- 在 Re=50000 下按最大升阻比排名前 10 的翼型
- 支持切换指标：`max_cl` / `min_cd` / `max_ld` / `avg_cl`
- 该过程体现：通过参数控制排序指标和返回条数，不需要前端手写复杂 SQL

**实验记录要点**：

- 解释存储过程相比直接写 SQL 的优势：参数化、可复用、减少网络传输
- 如果需要在其他 Re 值下比较，可以在 SQL 查询页手动执行：

```sql
CALL sp_compare_airfoils_by_re(200000, 'min_cd', 15);
```

---

### 实验 B：非法批量导入（验证拒绝）

**实验目的**：观察存储过程如何逐行校验并拒绝不合格数据。

**操作步骤**：

1. 点击 **「非法批量导入」** 按钮
2. 观察三段结果

**系统行为**：

```
暂存表插入两条数据：
  9900101: alpha_deg=0  ✅ 合法
  9900102: alpha_deg=99 ❌ 超出范围 [-20, 25]

CALL sp_import_performance_batch('demo_bad_batch'):
  → 检测到 invalid_count > 0 → 返回 'rejected'
  → 两条记录均不写入 performance_records
```

**预期结果**：

- Procedure status 显示 `status = 'rejected'`，`invalid_count = 1`
- Rejected rows 表显示 `perf_id=9900102` 的错误原因：`alpha_deg out of range [-20, 25]`
- Formal table verification 确认 `performance_records` 中**没有** 9900101 或 9900102

**重要说明**：这里显示 `rejected` 是正确结果，不是系统故障。该实验要证明存储过程能识别非法数据，并主动拒绝整批导入。只有出现非法数据仍然写入正式表，才说明实验失败。

**实验记录要点**：

- 强调**全有或全无**（all-or-nothing）：合法记录 9900101 也不会被"部分导入"
- 说明暂存表（staging table）模式的价值：先校验再导入，避免污染正式表

---

### 实验 C：合法批量导入（验证通过）

**实验目的**：与实验 B 对比，观察合法数据的完整导入流程。

**操作步骤**：

1. 点击 **「合法批量导入」** 按钮
2. 观察结果

**系统行为**：

```
暂存表插入两条数据：
  9900201: alpha_deg=-1 ✅ 合法
  9900202: alpha_deg= 1 ✅ 合法

CALL sp_import_performance_batch('demo_good_batch'):
  → 全部校验通过 → INSERT INTO performance_records
  → 更新暂存表 imported=1
  → 返回 'imported', imported_count = 2
```

**预期结果**：

- Procedure status 显示 `status = 'imported'`，`imported_count = 2`
- performance_records 中确认出现 9900201 和 9900202
- 暂存表中对应记录的 `imported` 状态被更新，说明这批数据已经完成导入流程

**对比分析**（实验 B vs 实验 C）：

| 维度 | 非法批量导入 | 合法批量导入 |
|------|------------|------------|
| 暂存数据条数 | 2 | 2 |
| 不合法条数 | 1（alpha=99 超范围） | 0 |
| 存储过程返回 | `rejected` | `imported` |
| 正式表结果 | 0 条写入 | 2 条写入 |
| 事务行为 | ROLLBACK（全部不写） | COMMIT（全部写入） |

### 存储过程实验截图要求

1. 截图 `sp_airfoil_performance_summary('ag03', 1)` 的统计结果
2. 截图 `sp_compare_airfoils_by_re(50000, 'max_ld', 10)` 的排名结果
3. 截图非法批量导入的 `status = rejected`、`invalid_count = 1` 和错误行
4. 截图非法批次在正式表中查询不到记录
5. 截图合法批量导入的 `status = imported`、`imported_count = 2`
6. 报告中说明：存储过程导入实验与事务实验不同，前者强调“暂存表校验 + 过程封装 + 全有或全无导入”，后者强调普通 SQL 事务的提交和回滚

---

## 第五部分：索引实验（简述）

> 对应说明书 **七.1**，入口在翼型总览页右下方的「索引实验」面板 + 「索引实验」标签页。

### 推荐实验流程

1. 在翼型总览页选择一个翼型，滚动到「索引实验」面板
2. 确认当前索引状态（点击「查看当前索引」）
3. 切换到「索引实验」标签页，点击「运行实验 SQL」记录耗时和 EXPLAIN
4. 回到翼型总览页，点击「删除填写的索引」（删除 `idx_perf_reynolds_alpha`）
5. 再次切换到索引实验页，点击「运行实验 SQL」，对比耗时和 EXPLAIN 中的 `key` 列
6. 点击「创建自定义索引」恢复索引

**观察重点**：

- EXPLAIN 输出中 `key` 列从 `NULL`（全表扫描）变为 `idx_perf_reynolds_alpha`（索引扫描）
- `rows` 列的显著下降
- 注意：由于数据量较小（~4200 条），执行时间可能波动，以 EXPLAIN 结果为准

**自定义索引实验**：

1. 在「索引实验」面板选择表（如 `performance_records`）
2. 勾选要建索引的列（如 `airfoil_id` + `version_id`）
3. 输入索引名，点击「创建自定义索引」
4. 在右侧 SQL 区域编写使用该索引的查询，验证 EXPLAIN 结果
5. 实验结束后点击「删除填写的索引」清理

---

## 实验数据记录模板

实验人员可按以下格式记录每次实验的结果，用于撰写实验报告。

### 事务实验记录

```
实验编号: TX-01
实验名称: 并发修改同一性能记录
操作时间: _______
实验结果:
  - User A UPDATE 耗时: ___ ms
  - User B UPDATE 耗时: ___ ms (等待约 ___ ms)
  - 最终 cl 值: ___
  - 是否出现死锁/超时: 是 / 否
截图: [附截图]
```

### 触发器实验记录

```
实验编号: TR-01
实验名称: 触发器拒绝非法异常记录
操作时间: _______
实验结果:
  - 触发器是否拒绝: 是 / 否
  - 错误信息: _________________
  - 引用的 performance record is_anomaly 值: ___
截图: [附截图]
```

### 存储过程实验记录

```
实验编号: SP-01
实验名称: 非法批量导入
操作时间: _______
实验结果:
  - sp_import 返回状态: rejected / imported
  - invalid_count: ___
  - 正式表验证: 0 条 / ___ 条写入
截图: [附截图]
```

---

## 常见问题排查

| 问题 | 原因 | 解决 |
|------|------|------|
| 按钮无反应 / 返回 403 | 未登录或权限不足 | 确认以 engineer/admin 登录 |
| 事务实验报 SQL 语法错误 | 手动编辑 SQL 时多加了分号或特殊字符 | 点击场景按钮恢复默认 SQL |
| 并发实验超时 | MySQL 连接被防火墙阻断 | 确认 MySQL 在本地运行且端口 3306 可访问 |
| 存储过程实验报 "already exists" | perf_id 与已有数据冲突 | 正常现象，后端会自动处理重复 |
| 索引删除后无法恢复 | 只删了索引 | 使用「创建自定义索引」重新创建，列选 `reynolds_number`, `alpha_deg` |

---

## 附录：SQL 参考（在 SQL 查询标签页手动执行）

以下 SQL 可在「SQL 查询」标签页中手动执行，用于补充验证或自主探索：

### 查看所有触发器

```sql
SELECT TRIGGER_NAME, EVENT_MANIPULATION, EVENT_OBJECT_TABLE, ACTION_TIMING
FROM information_schema.triggers
WHERE TRIGGER_SCHEMA = DATABASE()
ORDER BY EVENT_OBJECT_TABLE, ACTION_TIMING, EVENT_MANIPULATION;
```

### 查看所有视图

```sql
SELECT TABLE_NAME
FROM information_schema.views
WHERE TABLE_SCHEMA = DATABASE()
ORDER BY TABLE_NAME;
```

### 查看所有存储过程

```sql
SELECT ROUTINE_NAME, ROUTINE_TYPE
FROM information_schema.routines
WHERE ROUTINE_SCHEMA = DATABASE()
  AND ROUTINE_TYPE = 'PROCEDURE'
ORDER BY ROUTINE_NAME;
```

### 查看外键删除规则

```sql
SELECT table_name, constraint_name, referenced_table_name, delete_rule
FROM information_schema.referential_constraints
WHERE constraint_schema = DATABASE()
ORDER BY table_name, constraint_name;
```

### 查看表上的约束

```sql
SELECT TABLE_NAME, CONSTRAINT_NAME, CONSTRAINT_TYPE
FROM information_schema.table_constraints
WHERE TABLE_SCHEMA = DATABASE()
ORDER BY TABLE_NAME, CONSTRAINT_TYPE, CONSTRAINT_NAME;
```
