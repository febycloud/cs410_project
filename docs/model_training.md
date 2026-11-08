
目标是先完成两个传统 Information Retrieval baseline：

1. TF-IDF + Cosine Similarity
2. BM25

后续再使用 MiniLM 做 semantic retrieval，并与 baseline 结果进行比较。

---

## Step 3 目标

输入：

```text
CVE vulnerability description
```

输出：

```text
Top-K CWE categories
```

例如：

```text
Input:
An attacker can use ../ sequences to access files outside the intended directory.

Output:
1. CWE-22   Path Traversal
2. CWE-73   External Control of File Name or Path
3. CWE-20   Improper Input Validation
```

---

## Checkpoint 3.1 — 确认实验 Dataset

第一版 baseline 建议使用：

```text
/home/data/processed/cve_cwe_top50.csv
```

CWE corpus 使用：

```text
/home/data/processed/cwe_clean.csv
```

在 retrieval 中：

```text
CVE description = query
CWE search_text = document
```

不要把 CVE 当成 retrieval documents。

CWE document 主要使用：

```text
cwe_id
name
search_text
```

其中：

```text
search_text =
name + description + extended_description
```

---

## Checkpoint 3.2 — 建立 Train / Test Dataset

从：

```text
/home/data/processed/cve_cwe_top50.csv
```

建立固定的 train/test split。

建议：

```text
80% train
20% test
random_state = 42
```

虽然 TF-IDF 和 BM25 本身不需要传统意义上的训练，但固定 train/test split 可以：

- 保证不同 retrieval methods 使用完全相同的 test queries
- 避免后面 MiniLM 或参数调整时直接使用全部数据
- 让实验结果可以公平比较和重复

输出：

```text
/home/data/processed/train.csv
/home/data/processed/test.csv
```

建议字段：

```text
cve_id
cve_description
cwe_id
```

---

## Checkpoint 3.3 — TF-IDF Baseline

代码位置：

```text
src/models/tfidf_retriever.py
```

使用：

```python
sklearn.feature_extraction.text.TfidfVectorizer
```

流程：

```text
CWE search_text
        ↓
TF-IDF Vectorizer
        ↓
CWE TF-IDF vectors
        ↓

CVE description
        ↓
Same TF-IDF Vectorizer
        ↓
Query vector
        ↓
Cosine Similarity
        ↓
Rank CWE
        ↓
Top-K Results
```

需要支持：

```text
Top 1
Top 3
Top 5
```

建议统一接口：

```python
results = retriever.search(query, top_k=5)
```

返回格式：

```python
[
    {
        "cwe_id": "CWE-22",
        "name": "Path Traversal",
        "score": 0.73
    },
    {
        "cwe_id": "CWE-73",
        "name": "External Control of File Name or Path",
        "score": 0.51
    }
]
```

---

## Checkpoint 3.4 — BM25 Baseline

代码位置：

```text
src/models/bm25_retriever.py
```

使用：

```python
rank_bm25.BM25Okapi
```

CWE corpus：

```text
cwe_search_text
```

第一版 tokenizer 可以保持简单：

```python
text.lower().split()
```

流程：

```text
CWE search_text
        ↓
Tokenization
        ↓
BM25 Index
        ↓

CVE description
        ↓
Tokenization
        ↓
BM25 Scores
        ↓
Rank CWE
        ↓
Top-K Results
```

BM25 的返回格式应该与 TF-IDF 保持一致。

例如：

```python
[
    {
        "cwe_id": "CWE-89",
        "name": "SQL Injection",
        "score": 8.42
    }
]
```

---

## Checkpoint 3.5 — 统一 Retrieval Interface

TF-IDF 和 BM25 应该尽量使用相同调用方式：

```python
results = retriever.search(query, top_k=5)
```

这样后续加入 MiniLM 时可以继续保持：

```python
results = retriever.search(query, top_k=5)
```

统一接口方便：

- Evaluation
- API
- Web demo
- 不同 model 的性能比较

---

## Checkpoint 3.6 — Evaluation Metrics

对：

```text
/home/data/processed/test.csv
```

中的每一条 CVE：

```text
query = cve_description
ground truth = cwe_id
```

分别运行：

```text
TF-IDF
BM25
```

需要计算以下指标：

```text
Recall@1
Recall@3
Recall@5
MRR
nDCG@5
```

代码建议：

```text
src/evaluation/metrics.py
src/evaluation/evaluate_baselines.py
```

---

## Checkpoint 3.7 — 保存 Evaluation Results

TF-IDF metrics：

```text
/home/data/results/tfidf_metrics.csv
```

BM25 metrics：

```text
/home/data/results/bm25_metrics.csv
```

建议格式：

```text
model,recall@1,recall@3,recall@5,mrr,ndcg@5
TF-IDF,...
```

以及：

```text
model,recall@1,recall@3,recall@5,mrr,ndcg@5
BM25,...
```

---

## Checkpoint 3.8 — 保存 Prediction Results

为了后面分析错误，建议保存每一个 CVE 的 retrieval 结果。

TF-IDF：

```text
/home/data/results/tfidf_predictions.csv
```

BM25：

```text
/home/data/results/bm25_predictions.csv
```

建议字段：

```text
cve_id
query
ground_truth_cwe
rank_1_cwe
rank_2_cwe
rank_3_cwe
rank_4_cwe
rank_5_cwe
ground_truth_rank
```

也可以额外保存 score。

---

## Checkpoint 3.9 — Manual Sanity Check

除了自动 evaluation，还需要手动测试一些明显的 vulnerability descriptions。

### Path Traversal

输入：

```text
An attacker can use ../ sequences to access files outside the intended directory.
```

预期：

```text
CWE-22 Path Traversal
```

应该出现在 Top-K 中。

### SQL Injection

输入：

```text
Unsanitized user input is directly inserted into a SQL query.
```

预期：

```text
CWE-89 SQL Injection
```

### Cross-site Scripting

输入：

```text
User-controlled input is rendered in a web page without proper escaping.
```

预期：

```text
CWE-79 Cross-site Scripting
```

---

## Step 3 建议代码结构

```text
src/
├── data/
│   ├── data_util.py
│   ├── process_cve.py
│   ├── process_cwe.py
│   └── build_dataset.py
│
├── models/
│   ├── tfidf_retriever.py
│   └── bm25_retriever.py
│
└── evaluation/
    ├── metrics.py
    └── evaluate_baselines.py
```

---

## Step 3 最终需要生成的文件

### Code

```text
src/models/tfidf_retriever.py
src/models/bm25_retriever.py
src/evaluation/metrics.py
src/evaluation/evaluate_baselines.py
```

### Dataset

```text
/home/data/processed/train.csv
/home/data/processed/test.csv
```

### Results

```text
/home/data/results/tfidf_metrics.csv
/home/data/results/bm25_metrics.csv

/home/data/results/tfidf_predictions.csv
/home/data/results/bm25_predictions.csv
```

---

## Step 3 完成标准

第三步完成时需要满足：

- TF-IDF 可以输入 vulnerability description 并返回 Top-K CWE
- BM25 可以输入 vulnerability description 并返回 Top-K CWE
- 两个模型使用完全相同的 test set
- 支持 Top 1 / Top 3 / Top 5 retrieval
- 成功计算 Recall@1
- 成功计算 Recall@3
- 成功计算 Recall@5
- 成功计算 MRR
- 成功计算 nDCG@5
- Evaluation metrics 已保存到 `/home/data/results/`
- Prediction results 已保存到 `/home/data/results/`
- 至少完成几条 manual sanity check
- 代码可以重复运行并得到一致结果

---

## Step 3 完成后

下一阶段进入：

```text
Step 4 — MiniLM Semantic Retrieval
```

MiniLM 将使用 semantic embeddings 对 CVE description 和 CWE search text 进行向量匹配，然后与 TF-IDF 和 BM25 baseline 进行性能比较。
"""

path = Path("/mnt/data/STEP3_BASELINE_RETRIEVAL.md")
path.write_text(content, encoding="utf-8")
print(path)
