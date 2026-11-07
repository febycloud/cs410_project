# CVE → CWE 项目

输入一段漏洞描述，检索出最相关的 CWE 类别并排序。检索方法计划比较 TF-IDF、BM25、MiniLM（all-MiniLM-L6-v2）和 Hybrid。

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
│   └── cve_cwe_top50.csv      # Step 2
├── embeddings/
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
| `src/data/validate_result.py` | 生成 `validate_step2.py` 的原始文件 |
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

## 下一步

1. 决定主实验用 Top 25 还是 Top 50
2. 划分前的数据清洗：去掉 CWE 编号、标记标签泄漏、模板去重（详见 [docs/data_cleaning.md](docs/data_cleaning.md)）
3. 划分训练集和测试集
4. 实现 TF-IDF、BM25、MiniLM 和 Hybrid 检索
5. 用 Hit@1 / 3 / 5 和 MRR 评估
