# CVE → CWE 项目

输入一段漏洞描述，检索出最相关的 CWE 类别并排序。当前统一比较 TF-IDF、BM25 和 MiniLM（all-MiniLM-L6-v2）；Hybrid 可作为后续扩展。

## 已完成内容

- 已在 Debian VM 上配置 Python 3.13.5
- 已创建 Python 虚拟环境 `.venv`
- 已安装项目需要的主要 Python libraries
- 已建立共享数据目录 `/home/data/`
- 已下载并保存 NVD 2023–2025 CVE 数据
- 已下载并保存 MITRE CWE 数据
- 已完成 CWE 数据清洗
- 已完成 CVE 数据清洗
- 已完成 Step 2：CVE-CWE 匹配、CWE 分布统计、生成 Top 25 / Top 50 数据集，验证通过
- 已完成 leakage-controlled grouped train/test split
- 已实现 TF-IDF、BM25、MiniLM Top-50 retrieval、统一评估和 FastAPI 接口

## 数据目录

原始数据不修改，所有处理结果都放在 `processed/` 和 `results/`。数据不提交到 Git。

```text
/home/data/
├── raw/
│   ├── cwe/
│   │   └── CWE_comprehensive_view.csv
│   └── nvd/
│       ├── nvdcve-2.0-2023.json
│       ├── nvdcve-2.0-2024.json
│       └── nvdcve-2.0-2025.json
├── processed/
│   ├── cve_clean.csv          # Step 1
│   ├── cwe_clean.csv          # Step 1
│   ├── cve_cwe_pairs.csv      # Step 2：完整 master dataset
│   ├── cve_cwe_top25.csv      # Step 2
│   ├── cve_cwe_top50.csv      # Step 2：主实验候选集合
│   ├── train.csv              # leakage-controlled grouped split
│   └── test.csv               # official evaluation set
├── flagged_data/
│   ├── v1_train.csv           # 旧的 leakage-prone split（仅历史参考）
│   └── v1_test.csv
├── embeddings/
│   └── minilm/
│       ├── cwe_embeddings.npy
│       └── cwe_metadata.csv
└── results/
    ├── cwe_distribution.csv   # Step 2：每个 CWE 的 CVE 数量
    └── dataset_summary.txt    # Step 2：统计结果和验证结果
```

## 代码

| 文件 | 作用 |
| --- | --- |
| `src/data/data_util.py` | 共用的路径和工具函数 |
| `src/data/process_cwe.py` | Step 1：清洗 MITRE CWE 数据 → `cwe_clean.csv` |
| `src/data/process_cve.py` | Step 1：清洗 NVD CVE 数据 → `cve_clean.csv` |
| `src/data/build_dataset.py` | Step 2：匹配 CVE 和 CWE，生成 pair / Top 25 / Top 50 数据集和分布统计，并做验证 |
| `src/data/validate_step2.py` | Step 2：独立检查所有输出文件 |
| `src/data/validate_result.py` | 兼容旧命令，调用规范的 `validate_step2.py` 验证器 |
| `src/data/split_dataset.py` | 生成官方 grouped train/test split，并标记 `leak_flag` |
| `src/models/` | TF-IDF、BM25、MiniLM Top-50 retrievers |
| `src/evaluation/` | 统一评估 `all` 和 `clean` subsets |
| `src/api/main.py` | FastAPI JSON API |
| `docs/data_cleaning.md` | Step 2 详细统计和划分前的数据清洗计划 |

## 如何运行

在项目根目录激活 `.venv`：

```bash
cd ~/cs410_project
source .venv/bin/activate
```

**Step 1：数据清洗**（在 `src/data` 下运行）

```bash
cd src/data
python process_cwe.py
python process_cve.py
```

**Step 2：生成最终数据集**

```bash
python build_dataset.py
```

运行结束时会打印 Dataset Summary 和 Final Validation，同样的内容保存在 `/home/data/results/dataset_summary.txt`。最后一行显示 `All checks passed. Step 2 complete.` 表示成功。

**Step 2：独立验证**（回到项目根目录）

```bash
cd ~/cs410_project
python src/data/validate_step2.py
```

最后显示 `STEP 2 VALIDATION PASSED` 表示所有输出文件都正确。

## Step 2 结果

| 数据集 | CVE 数量 | CWE 类别 |
| --- | --- | --- |
| `cve_cwe_pairs.csv` | 92,793 | 610 |
| `cve_cwe_top25.csv` | 66,369 | 25 |
| `cve_cwe_top50.csv` | 77,711 | 50 |

匹配阶段删除了 142 条（0.15%）。详细统计和注意事项见 [docs/data_cleaning.md](docs/data_cleaning.md)。

## Retrieval、评估与 API

主实验固定使用 Top 50。以下命令均从项目根目录运行：

```bash
python -m src.data.split_dataset
python -m src.evaluation.evaluate_baselines
uvicorn src.api.main:app
```

评估计算 Recall@1/3/5、MRR 和 nDCG@5。模型比较以
`test[test["leak_flag"] == 0]` 的 `clean` subset 为准，同时保存 `all` 结果供参考。
