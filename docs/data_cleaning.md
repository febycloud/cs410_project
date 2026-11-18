# 数据说明与划分前清洗

本文件记录 Step 2 结果的详细统计，以及划分训练 / 测试集前的数据清洗。划分前的清洗已在 v2（分支 `v2_Clean_Data_Leakage`）中实现。

相关文档：
- 项目概况和运行方法：[README](../README.md)
- 泄漏分析的完整数据和实验：[data_leakage_findings.md](data_leakage_findings.md)
- v2 改动了哪些文件：[v2_changes.md](v2_changes.md)

## Step 2 结果详情

### 匹配阶段

| 项目 | 数量 |
| --- | --- |
| 匹配前 CVE 记录 | 92,935 |
| 匹配后 CVE 记录 | 92,793 |
| 删除（`cwe_id` 不在 `cwe_clean.csv` 里） | 142 |
| 匹配前 CWE 类别 | 632 |
| 匹配后 CWE 类别 | 610 |

被删除的 142 条主要是 CWE-264、CWE-840、CWE-16 等 Category 或已废弃的 ID，只占 0.15%，不需要额外映射。

### 各数据集

| 数据集 | CVE 数量 | 占全部 | 最小类别 |
| --- | --- | --- | --- |
| `cve_cwe_pairs.csv` | 92,793 | 100% | — |
| `cve_cwe_top25.csv` | 66,369 | 71.5% | 784 |
| `cve_cwe_top50.csv` | 77,711 | 83.7% | 261 |

### 最常见的 10 个 CWE

| 排名 | CWE | 名称 | CVE 数量 |
| --- | --- | --- | --- |
| 1 | CWE-79 | Cross-site Scripting | 18,930 |
| 2 | CWE-89 | SQL Injection | 5,975 |
| 3 | CWE-862 | Missing Authorization | 4,824 |
| 4 | CWE-352 | Cross-Site Request Forgery (CSRF) | 4,232 |
| 5 | CWE-787 | Out-of-bounds Write | 2,767 |
| 6 | CWE-125 | Out-of-bounds Read | 2,519 |
| 7 | CWE-22 | Path Traversal | 2,466 |
| 8 | CWE-416 | Use After Free | 2,381 |
| 9 | CWE-476 | NULL Pointer Dereference | 2,076 |
| 10 | CWE-78 | OS Command Injection | 1,789 |

完整排名见 `/home/data/results/cwe_distribution.csv`，完整统计见 `/home/data/results/dataset_summary.txt`。

### 需要注意

- **类别不均衡**：CWE-79 一个类就占 Top 50 的 24.4%。最大类和最小类的条数比：Top 25 约 24 倍，Top 50 约 73 倍。评估时除了总体 Hit@k，还应报告按类别平均的指标。
- **父子类别**：Top 50 里有一些父子关系的类别，比如 CWE-119 和 CWE-787 / 125 / 120，CWE-77 和 CWE-78，CWE-284 和 CWE-862 / 863。这些很难区分，Hit@3 和 Hit@5 会比 Hit@1 更能反映效果。

## 划分前的数据清洗（v2 已完成）

主实验使用 Top 50。下面三项都在 `src/data/split_dataset.py` 里完成，输出到 `/home/data/processed/v2_clean_data_leakage/train.csv` 和 `test.csv`，不会覆盖 v1 的划分。

| 问题 | 条数（Top 50） | v2 的处理 |
| --- | --- | --- |
| 描述里写着 CWE 编号 | 555（0.7%） | 删除编号 |
| 描述里写着 CWE 官方全名 | 8,377（10.8%） | 保留文字，加 `leak_flag` 标记 |
| 模板描述（同一句话、不同产品） | 8,816（11.3%），2,465 组 | 按 `norm_key` 分组划分，同一组不会同时出现在训练集和测试集 |

### 1. 去掉描述里的 CWE 编号

有些 CVE 描述里直接写着 "CWE-79" 这样的编号，等于把答案写进了查询。v2 从 `cve_description` 里删掉了这些编号，共 555 条。TF-IDF 和 BM25 的 `search()` 也会对用户输入做同样的处理。

### 2. 标记描述里写着 CWE 官方全名的记录

Patchstack 等 CNA 的模板描述常以 CWE 官方全名开头，例如 "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in …"。`cwe_search_text` 也以这个名字开头，所以 TF-IDF / BM25 几乎一定能答对，分数会虚高。

- 不删除，而是新增一列 `leak_flag`：0 = 没有，1 = 写着自己 CWE 的全名，2 = 写着别的 CWE 的全名
- 只匹配至少 6 个词的官方全名；"Use After Free"、"Missing Authorization" 这类短名称本身就是自然说法，不算泄漏
- 不删除名称的原因：删掉以后这些描述几乎不剩内容，TF-IDF Recall@1 会从 0.97 掉到 0.27，反而失真

实测影响（v2 测试集，Recall@1）：

| 模型 | 全部 | 只看 `leak_flag = 0` | 虚高 |
| --- | --- | --- | --- |
| TF-IDF | 0.656 | 0.617 | 3.9 个百分点 |
| BM25 | 0.478 | 0.420 | 5.8 个百分点 |

**评估规则**：每个指标都同时报告"全部"和"`leak_flag = 0`"两组，比较模型时用后者。

### 3. 模板去重

批量提交的 CVE 描述除了产品名、版本号几乎一样。同一句话如果同时出现在训练集和测试集，会造成泄漏。

- 文本标准化后生成 `norm_key`：小写，引号内容、URL 和独立的数字 / 版本号替换掉
- 用 `StratifiedGroupKFold`（5 折，seed 42）划分：20% 测试集，按 `norm_key` 分组，同时按 `cwe_id` 分层
- 不用相似度聚类，因为模板描述会被链式合并成巨大的组

实测影响：v1 的随机划分中，测试集有 10.3% 的记录在训练集里有同一句话，最近邻 Recall@1 因此虚高约 3 个百分点（0.628 对 v2 的 0.598）。TF-IDF 和 BM25 只检索 CWE 文档、不用训练集，所以不受这一项影响；以后用到训练集的模型（例如微调 MiniLM）会受影响。

### v2 划分结果

| 项目 | 数值 |
| --- | --- |
| 训练集 / 测试集 | 62,168 / 15,543（测试集 20.0%） |
| 同时出现在两边的 CVE / 模板 | 0 / 0 |
| CWE 类别 | 两边都是 50 个，比例差异不超过 0.01 个百分点 |
| 没有泄漏的测试记录（`leak_flag = 0`） | 13,915 |
| 测试集最小类别 | CWE-319、CWE-522（各 52 条） |
| 可复现 | 重复运行得到完全相同的文件 |

输出列：`cve_id`、`cve_description`（作为查询）、`cwe_id`、`year`、`leak_flag`、`norm_key`（只用于分组，不能作为模型特征）。

运行方法：

```bash
cd src/data
python split_dataset.py            # Top 50
python split_dataset.py --top 25   # Top 25，输出 train_top25.csv / test_top25.csv
```

## 已知局限

v2 解决了上面三个问题，但还有以下几点，写报告时需要说明：

1. **近似重复仍会跨越划分。** `norm_key` 只能合并标准化后完全相同的描述。产品名没有加引号的模板（例如 "Missing Authorization vulnerability in Foo Plugin"）不会被分到同一组。测试集中有 21.8% 的记录，在训练集里能找到相似度 ≥ 0.9 的描述；这些记录的最近邻 Recall@1 是 0.823，其余记录是 0.549。这一点不影响 TF-IDF / BM25，但会影响以后用到训练集的模型。
2. **大模板组集中在测试集。** 最大的模板组（323 条 Adobe Experience Manager XSS 描述）整组落在测试集里。这些记录几乎得到相同的预测，会放大 CWE-79 的权重。
3. **总体指标掩盖了弱类别。** TF-IDF 在 `leak_flag = 0` 上的 Recall@1，按记录平均是 0.617，按类别平均只有 0.470。最弱的类别如 CWE-770（0.05）、CWE-120（0.06）、CWE-732（0.10）、CWE-287（0.12）。CWE-79 一个类就占干净测试集的 20.7%。
4. **`leak_flag` 是规则判断。** 只检查完整的官方名称（至少 6 个词），改写过的名称或部分名称不会被标记。

可能的改进方向：用更宽松的方式合并近似模板（例如去掉 "vulnerability in … allows" 中间的产品名后再生成 `norm_key`）；评估时增加按类别平均（macro）的指标；限制每个模板组在测试集中的条数。

## 可以不做的

- 多标签记录：Step 1 已只保留单 CWE 记录
- 类别不均衡：划分时按类别分层，评估时报告按类别平均的指标
- 小写、去停用词等文本处理：留到建模阶段，按各模型的需要处理
