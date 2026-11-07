# 数据说明与划分前清洗

本文件记录 Step 2 结果的详细统计，以及划分训练 / 测试集前计划做的数据清洗。项目概况和运行方法见 [README](../README.md)。

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

## 划分前的数据清洗

需要做到什么程度，取决于模型会不会用到训练集里的 CVE 描述（比如用它们扩充 CWE 文档或调参）。建议先写一个只读的检查脚本，统计下面第 2、3 项在数据里的比例，再决定。

### 1. 去掉描述里的 CWE 编号（必须）

有些 CVE 描述里直接写着 "CWE-79" 这样的编号，等于把答案写进了查询。直接删掉这些编号。

### 2. 标记描述里写着 CWE 官方全名的记录（强烈建议）

Patchstack 等 CNA 的模板描述常以 CWE 官方全名开头，例如 "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in …"。`cwe_search_text` 也以这个名字开头，所以 TF-IDF / BM25 的分数会虚高。不管用不用训练集都有影响。

- 不删除，新增一列 `leak_flag` 标记
- 只匹配较长的官方全名；"Use After Free"、"Missing Authorization" 这类短名称本身就是自然说法，不算泄漏
- 评估时分开报告：全部测试集、只看没有泄漏的记录

### 3. 模板去重（用训练集时必须）

批量提交的 CVE 描述除了产品名、版本号几乎一样。同一句话如果同时出现在训练集和测试集，会造成泄漏。

- 文本标准化后生成 `norm_key`：小写、引号内容和数字 / 版本号替换掉
- 划分时按 `norm_key` 分组，保证同一组不会同时出现在训练集和测试集
- 不用相似度聚类，因为模板描述会被链式合并成巨大的组，误删大量数据

### 可以不做的

- 多标签记录：Step 1 已只保留单 CWE 记录
- 类别不均衡：划分时按类别分层，评估时报告按类别平均的指标
- 小写、去停用词等文本处理：留到建模阶段，按各模型的需要处理
