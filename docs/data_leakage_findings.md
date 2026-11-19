# Data Leakage Findings

Read-only analysis of the real Step 2 output `cve_cwe_top50.csv` (77,711 CVEs, 50 CWE classes; 2023: 21,417 / 2024: 28,254 / 2025: 28,040), followed by the fix implemented in `v2_Clean_Data_Leakage`.

The dataset was rebuilt from `cve_clean.csv` and `cwe_clean.csv` with `build_dataset.py`; all counts match the run on the shared VM exactly.

## 1. What leaks

| Issue | Rows | Notes |
| --- | --- | --- |
| Description contains a CWE ID (e.g. "CWE-79") | 554 (0.7%) | The answer is written in the query |
| Description contains its own official CWE name (≥ 6 words) | 8,377 (10.8%) | Mostly CWE-98 (78% of its rows), CWE-79 (25%), CWE-434, CWE-601, CWE-532 (about 22% each) |
| Same, counting names with ≥ 4 words | 12,928 (16.6%) | Adds natural phrases such as "Cross-Site Request Forgery (CSRF)"; not real leakage |
| Rows in a duplicate-template group (`norm_key`) | 8,816 (11.3%) | 2,465 groups; the largest has 323 Adobe Experience Manager XSS descriptions |
| Same template text in more than one year | 2,338 (3.0%) | Would leak across a year-based split |

Why the official name matters: many CNA templates (e.g. Patchstack) start with the full CWE name, such as "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in …". Every `cwe_search_text` also starts with that name, so lexical retrievers (TF-IDF, BM25) end up matching strings rather than understanding the description.

Only names with at least 6 words are treated as leakage. Short names such as "Use After Free" or "Missing Authorization" are how people normally describe these bugs.

## 2. Measured impact

### Experiment A: name leakage (no training data)

TF-IDF retrieval. The query is the CVE description; the documents are the 50 CWE `search_text` entries.

| Subset | Rows | Hit@1 | Hit@5 | MRR |
| --- | --- | --- | --- | --- |
| All rows | 77,711 | 0.663 | 0.818 | 0.737 |
| Rows with the official name in the text | 8,377 | 0.970 | 1.000 | 0.985 |
| Clean rows | 69,334 | 0.626 | 0.796 | 0.707 |
| Name rows after masking the name | 8,377 | 0.274 | 0.751 | 0.431 |

- Rows that contain the official name are almost always ranked first (97% Hit@1).
- These rows inflate overall Hit@1 by about 3.7 points (0.663 vs 0.626 on clean rows).
- Masking the name is not a good fix: it leaves too little text in those descriptions (Hit@1 drops to 0.274). Report results on clean rows instead.

### Experiment B: template leakage (uses training data)

The model is a 1-nearest-neighbour search over the training CVE descriptions (TF-IDF), evaluated on an 80/20 split.

| Split | Test rows | Test rows whose template is in train | Hit@1 |
| --- | --- | --- | --- |
| Random split | 15,543 | 10.3% | 0.628 |
| – rows whose template is in train | 1,594 | 100% | 0.878 |
| – rows with a new template | 13,949 | 0% | 0.599 |
| Split grouped by `norm_key` | 15,426 | 0% | 0.597 |

- A random split puts the same template in both train and test for 10% of the test rows. Those rows score 0.878 Hit@1, compared with about 0.60 for the rest.
- As a result, the random split inflates overall Hit@1 by about 3 points.

### Why this matters

- A 3–4 point inflation is about the size of the expected gap between TF-IDF, BM25, MiniLM and Hybrid, so the leakage could change which method looks best.
- TF-IDF and BM25 benefit most because they rely on exact word overlap, which makes the comparison with MiniLM unfair.
- Per-class results for heavily affected classes (e.g. CWE-98) are mostly a measure of the leakage itself.

## 3. What Step 1 and Step 2 already cover

Neither step addresses leakage. They ensure data integrity: valid and normalized CWE IDs, no empty values, no duplicate `cve_id`, and labels that exist in `cwe_clean.csv`. Removing duplicate `cve_id` values does not remove different CVEs that share the same template text, and Step 2 does not split the data.

## 4. Fix: v2_Clean_Data_Leakage

Implemented in `src/data/split_dataset.py` on the Git branch `v2_Clean_Data_Leakage`. v1 is tagged `v1_original`.

| Leakage | Handling |
| --- | --- |
| CWE IDs in the description | Removed from `cve_description` (555 rows) |
| Official CWE name in the description | Kept, and marked with `leak_flag`: 1 = its own CWE's name, 2 = another CWE's name, 0 = clean |
| Template descriptions | The split is grouped by `norm_key` so a template never appears in both train and test |

The split uses `StratifiedGroupKFold` (5 folds, seed 42): 20% test, grouped by `norm_key` and stratified by `cwe_id`.

### Input and output

v2 reads the same input as v1 but writes to its own folders, so the v1 split is never overwritten.

| | Path |
| --- | --- |
| Input | `/home/data/processed/cve_cwe_top50.csv` (`--top 25` uses `cve_cwe_top25.csv`) |
| Train / test | `/home/data/processed/train.csv`, `/home/data/processed/test.csv` |
| Top 25 | `/home/data/processed/train_top25.csv`, `/home/data/processed/test_top25.csv` |
| Summary | `/home/data/results/split_summary.txt` |

Output columns: `cve_id`, `cve_description` (use as the query), `cwe_id`, `year`, `leak_flag`, `norm_key` (used for grouping only, not as a feature).

### Result on the real Top 50 data

| Item | Value |
| --- | --- |
| Train / test rows | 62,168 / 15,543 (20.0% test) |
| `cve_id` in both train and test | 0 |
| Templates in both train and test | 0 |
| CWE classes | All 50 in both train and test |
| Class share difference between train and test | ≤ 0.01 percentage points |
| Clean test rows (`leak_flag = 0`) | 13,915 |
| Smallest test classes | CWE-319, CWE-522 (52 rows each) |
| 1-NN Hit@1 on the test set | 0.598 (0.628 with the old random split) |
| Reproducible | Yes; rerunning gives identical files |

## 5. Evaluation rule

Report every metric on all test rows **and** on clean rows only:

```python
import pandas as pd

test = pd.read_csv("/home/data/processed/test.csv")
evaluate(test)                          # all test rows
evaluate(test[test["leak_flag"] == 0])  # clean rows only: the honest number
```

Only `cve_description` is used as the query. Never add `cwe_name` or `cwe_search_text` to the query, because they contain the answer.

## 6. Baseline results on the v2 test set

`src/evaluation/evaluate_baselines.py`, Top 50, 15,543 test queries (13,915 clean).

| Model | Subset | n | Recall@1 | Recall@3 | Recall@5 | MRR | nDCG@5 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TF-IDF | all | 15,543 | 0.656 | 0.769 | 0.811 | 0.728 | 0.739 |
| TF-IDF | clean | 13,915 | 0.617 | 0.742 | 0.789 | 0.697 | 0.709 |
| TF-IDF | leak | 1,625 | 0.996 | 1.000 | 1.000 | 0.998 | 0.998 |
| BM25 | all | 15,543 | 0.478 | 0.619 | 0.691 | 0.580 | 0.591 |
| BM25 | clean | 13,915 | 0.420 | 0.575 | 0.656 | 0.532 | 0.544 |
| BM25 | leak | 1,625 | 0.980 | 0.995 | 0.996 | 0.988 | 0.990 |

- Name leakage inflates Recall@1 by 3.9 points for TF-IDF and 5.8 points for BM25. BM25 relies more on exact word overlap, so it gains more from the leak.
- On the old random split (v1 test set, all rows) the numbers are almost the same (TF-IDF 0.663, BM25 0.484). That is expected: these retrievers search only the 50 CWE documents and never use training CVEs, so template leakage between train and test does not affect them. It will matter for any model that uses training data (e.g. MiniLM fine-tuning or enriching CWE documents with training CVEs).
- The BM25 numbers were produced with a stand-in that implements the same BM25Okapi formula as `rank_bm25`; rerun on the VM to confirm them.
