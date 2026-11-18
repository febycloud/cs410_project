# v2_Clean_Data_Leakage — Change Log

v2 removes data leakage from the train/test split and from retriever queries, and adds the baseline evaluation (Checkpoints 3.6–3.8 in [model_training.md](model_training.md)). The analysis behind these changes is in [data_leakage_findings.md](data_leakage_findings.md).

| | |
| --- | --- |
| Branch | `v2_Clean_Data_Leakage` |
| Based on | tag `v1` = commit `0ee03b1` ("added tfidf and bm25 retriever") |
| Main commit | `88f8a1d` "v2: leakage-aware split, CWE-ID query cleaning, baseline evaluation" |
| Status | Pull Request to `main`, waiting for review |

## Why v2

The v1 data is clean in the integrity sense (valid labels, no duplicate IDs), but it leaks the answer in three ways. Measured on the Top 50 dataset:

| Leakage | Rows | Effect |
| --- | --- | --- |
| CWE ID written in the description ("CWE-79") | 554 (0.7%) | The answer is in the query |
| Official CWE name written in the description | 8,377 (10.8%) | TF-IDF ranks these first 97% of the time; inflates Recall@1 by 3.9 points (TF-IDF) and 5.8 points (BM25) |
| Template descriptions (same sentence, different product) | 8,816 (11.3%) | The random split puts 10% of test rows next to an identical training row; inflates 1-NN Recall@1 by about 3 points |

## Changed files

| File | Change |
| --- | --- |
| `src/data/split_dataset.py` | **Rewritten.** Leakage-aware split (details below). Writes to a new v2 folder instead of overwriting the v1 split. |
| `src/models/tfidf_retriever.py` | `search()` removes CWE IDs from the query before searching. Nothing else changed. |
| `src/models/bm25_retriever.py` | Same change as the TF-IDF retriever. |
| `src/evaluation/metrics.py` | **New.** Recall@1/3/5, MRR, nDCG@5. |
| `src/evaluation/evaluate_baselines.py` | **New.** Evaluates TF-IDF and BM25 and saves metrics and predictions. |
| `docs/data_leakage_findings.md` | **New.** Leakage analysis, measured impact, fix and baseline results. |
| `docs/v2_changes.md` | **New.** This file. |
| `.gitignore` | **New.** Ignores `__pycache__/`, `*.pyc` and `*.tar.gz`. |

The `__pycache__` files that had been committed by mistake are removed from Git.

**Unchanged:** `process_cve.py`, `process_cwe.py`, `data_util.py`, `build_dataset.py`, `validate_result.py`, `validate_step2.py`, `src/api/main.py`. Steps 1 and 2 produce exactly the same files as in v1.

## 1. Train/test split (`split_dataset.py`)

| | v1 | v2 |
| --- | --- | --- |
| Method | `train_test_split`, stratified by `cwe_id` | `StratifiedGroupKFold` (5 folds, seed 42): stratified by `cwe_id` **and** grouped by template (`norm_key`) |
| Test share | 20% | 20% |
| CWE IDs in the description | Kept | Removed |
| Official CWE name in the description | Not detected | Kept, marked with `leak_flag` |
| Same template in train and test | Possible (10% of test rows) | Never |
| Output columns | `cve_id`, `cve_description`, `cwe_id` | Same three, plus `year`, `leak_flag`, `norm_key` |
| Output folder | `/home/data/processed/` | `/home/data/processed/v2_clean_data_leakage/` |
| Built-in checks | Row and class counts printed | 9 checks, plus a summary saved to `results/v2_clean_data_leakage/split_summary.txt`; exits with an error if a check fails |
| Top 25 | Not supported | `--top 25` writes `train_top25.csv` / `test_top25.csv` |

`leak_flag` values:

| Value | Meaning |
| --- | --- |
| 0 | Clean |
| 1 | The description contains the official name of its own CWE |
| 2 | The description contains the official name of another CWE |

Only official names with at least 6 words count. Short names such as "Use After Free" are normal wording, not leakage. Names are flagged rather than removed, because removing them leaves almost no text in those descriptions.

`norm_key` is the description in lower case, with quoted text, URLs and standalone numbers/versions replaced. It is used only for grouping; do not use it as a model feature.

## 2. Retrievers (`tfidf_retriever.py`, `bm25_retriever.py`)

`search()` now calls `remove_cwe_ids()` on the query, the same cleaning the split applies to the test set:

```text
"SQL injection (CWE-89) in login"  ->  "SQL injection in login"
```

- Ranking, indexing and the candidate set (the 50 CWEs in `cve_cwe_top50.csv`) are unchanged.
- The API behaves the same, except that a query consisting only of a CWE ID (e.g. `"CWE-79"`) now returns HTTP 400 "Query cannot be empty" instead of a ranking.
- The retrievers never read `train.csv` or `test.csv`, so the new split does not affect them directly.

## 3. Evaluation (`src/evaluation/`)

Implements Checkpoints 3.6–3.8. Every test query is ranked against all 50 CWEs, and the rank of the correct CWE gives the metrics.

Metrics are reported for three subsets of the v2 test set:

| Subset | Rows | Meaning |
| --- | --- | --- |
| `all` | 15,543 | Every test row |
| `clean` | 13,915 | `leak_flag == 0`; **use this to compare models** |
| `leak` | 1,625 | `leak_flag == 1` |

Output files in `/home/data/results/v2_clean_data_leakage/`:

| File | Content |
| --- | --- |
| `tfidf_metrics.csv`, `bm25_metrics.csv` | `model, subset, n, recall@1, recall@3, recall@5, mrr, ndcg@5` |
| `tfidf_predictions.csv`, `bm25_predictions.csv` | `cve_id, query, ground_truth_cwe, rank_1_cwe … rank_5_cwe, rank_1_score, ground_truth_rank, leak_flag` |
| `metrics_summary.csv` | Both models together |

`--split v1` evaluates the v1 test set instead and writes to `/home/data/results/`. Check that folder first, so you don't overwrite someone else's results.

## Results (Top 50)

**Split:** 62,168 train / 15,543 test rows. All 50 classes are in both sets, and class shares differ by at most 0.01 percentage points. No CVE or template appears in both sets. The smallest test classes, CWE-319 and CWE-522, have 52 rows each. Rerunning gives identical files.

**Baselines on the v2 test set:**

| Model | Subset | Recall@1 | Recall@3 | Recall@5 | MRR | nDCG@5 |
| --- | --- | --- | --- | --- | --- | --- |
| TF-IDF | all | 0.656 | 0.769 | 0.811 | 0.728 | 0.739 |
| TF-IDF | clean | 0.617 | 0.742 | 0.789 | 0.697 | 0.709 |
| BM25 | all | 0.478 | 0.619 | 0.691 | 0.580 | 0.591 |
| BM25 | clean | 0.420 | 0.575 | 0.656 | 0.532 | 0.544 |

The BM25 numbers were first measured with a stand-in for `rank_bm25`. If the VM run differs, the values in `results/v2_clean_data_leakage/metrics_summary.csv` are authoritative.

## How to run v2

From the project root, with `.venv` activated:

```bash
git checkout v2_Clean_Data_Leakage

# Steps 1-2 are unchanged; rerun only if the raw data changed
cd src/data
python split_dataset.py          # v2 split -> processed/v2_clean_data_leakage/
cd ../..

python -m src.evaluation.evaluate_baselines
```

## Data folders

v1 and v2 data live side by side; v2 never overwrites v1.

```text
/home/data/
├── processed/
│   ├── cwe_clean.csv, cve_cwe_top50.csv, ...   # shared inputs (Steps 1-2, unchanged)
│   ├── train.csv, test.csv                     # v1 split
│   └── v2_clean_data_leakage/
│       └── train.csv, test.csv                 # v2 split
└── results/
    ├── ...                                     # v1 results
    └── v2_clean_data_leakage/
        ├── split_summary.txt
        ├── metrics_summary.csv
        └── tfidf_* / bm25_* metrics and predictions
```

## Going back to v1

| What | Command |
| --- | --- |
| Look at the v1 code | `git checkout v1` (back with `git checkout v2_Clean_Data_Leakage`) |
| Restore one v1 file | `git checkout v1 -- src/data/split_dataset.py` |
| v1 data | Still in `/home/data/processed/train.csv` and `test.csv`; v1's split is deterministic (seed 42), so rerunning the v1 code recreates it exactly |

## Notes for the next steps

- Report every model on `all` **and** `clean`. Compare models on `clean`.
- Template leakage did not change the TF-IDF/BM25 results, because they only search the CWE documents. It will matter for any model that learns from training CVEs, such as fine-tuned MiniLM or CWE documents enriched with training CVEs. Use the v2 `train.csv` for those.
- Only `cve_description` may be used as the query. Never add `cwe_name` or `cwe_search_text`; they contain the answer.
- `README.md` still describes v1 and will be updated when v2 is merged.
