"""
Evaluate the TF-IDF and BM25 baselines (Checkpoints 3.6 - 3.8), v2_Clean_Data_Leakage.

For every CVE in the test set:
    query        = cve_description
    ground truth = cwe_id
Each retriever ranks all candidate CWEs; the rank of the correct CWE gives
Recall@1/3/5, MRR and nDCG@5 (see metrics.py).

Leakage-aware reporting (v2):
    The v2 test set has a leak_flag column (see docs/data_leakage_findings.md).
    Metrics are reported for three subsets:
        all     every test row
        clean   leak_flag == 0   <- the honest number to compare models on
        leak    leak_flag == 1   (description contains its own official CWE name)

Test sets:
    --split v2 (default)  /home/data/processed/v2_clean_data_leakage/test.csv
                          results -> /home/data/results/v2_clean_data_leakage/
    --split v1            /home/data/processed/test.csv (old random split, no leak_flag)
                          results -> /home/data/results/

Outputs (in the results folder above):
    tfidf_metrics.csv, bm25_metrics.csv          one row per subset
    tfidf_predictions.csv, bm25_predictions.csv  top-5 results for every CVE
    metrics_summary.csv                          both models together

Usage (from the project root, with .venv activated):
    python -m src.evaluation.evaluate_baselines
    python -m src.evaluation.evaluate_baselines --split v1
    python -m src.evaluation.evaluate_baselines --models tfidf
"""
import argparse
import os
import time
from pathlib import Path

import numpy as np
import pandas as pd

from src.evaluation.metrics import compute_metrics


DATA_ROOT = Path(os.getenv("DATA_ROOT", "/home/data"))
PROCESSED = DATA_ROOT / "processed"

# CWE documents and candidate list are the same for v1 and v2.
CWE_FILE = PROCESSED / "cwe_clean.csv"
CANDIDATE_FILE = PROCESSED / "cve_cwe_top50.csv"

SPLITS = {
    "v1": {
        "test": PROCESSED / "test.csv",
        "results": DATA_ROOT / "results",
    },
    "v2": {
        "test": PROCESSED / "v2_clean_data_leakage" / "test.csv",
        "results": DATA_ROOT / "results" / "v2_clean_data_leakage",
    },
}

METRIC_COLUMNS = ["recall@1", "recall@3", "recall@5", "mrr", "ndcg@5"]
TOP_N_SAVED = 5  # predictions file keeps the top 5 results per query


def load_retriever(name):
    """Import lazily, so evaluating only TF-IDF does not need rank_bm25."""
    if name == "tfidf":
        from src.models.tfidf_retriever import TfidfRetriever
        return "TF-IDF", TfidfRetriever(cwe_file=CWE_FILE, candidate_file=CANDIDATE_FILE)
    if name == "bm25":
        from src.models.bm25_retriever import BM25Retriever
        return "BM25", BM25Retriever(cwe_file=CWE_FILE, candidate_file=CANDIDATE_FILE)
    raise ValueError(f"Unknown model: {name}")


def rank_all(retriever, test):
    """
    Run every test query and return one prediction row per CVE.
    All candidates are retrieved so the rank of the correct CWE is always known.
    """
    n_candidates = retriever.get_candidate_count()
    rows = []

    for row in test.itertuples(index=False):
        try:
            results = retriever.search(query=row.cve_description, top_k=n_candidates)
        except ValueError:
            results = []  # e.g. the query has no usable tokens: counts as not found

        ranked_ids = [r["cwe_id"] for r in results]
        true_rank = ranked_ids.index(row.cwe_id) + 1 if row.cwe_id in ranked_ids else np.inf

        pred = {
            "cve_id": row.cve_id,
            "query": row.cve_description,
            "ground_truth_cwe": row.cwe_id,
        }
        for i in range(TOP_N_SAVED):
            pred[f"rank_{i + 1}_cwe"] = ranked_ids[i] if i < len(ranked_ids) else ""
        pred["rank_1_score"] = results[0]["score"] if results else np.nan
        pred["ground_truth_rank"] = true_rank
        if hasattr(row, "leak_flag"):
            pred["leak_flag"] = row.leak_flag
        rows.append(pred)

    return pd.DataFrame(rows)


def metrics_by_subset(model_name, predictions):
    """Metrics for all rows, and for clean / leak rows when leak_flag exists."""
    subsets = [("all", predictions)]
    if "leak_flag" in predictions.columns:
        flag = predictions["leak_flag"].astype(int)
        subsets += [("clean", predictions[flag == 0]), ("leak", predictions[flag == 1])]

    out = []
    for subset, part in subsets:
        m = compute_metrics(part["ground_truth_rank"].to_numpy())
        out.append({"model": model_name, "subset": subset, "n": len(part), **m})
    return pd.DataFrame(out)[["model", "subset", "n"] + METRIC_COLUMNS]


def main():
    parser = argparse.ArgumentParser(description="Evaluate TF-IDF and BM25 baselines")
    parser.add_argument("--split", choices=["v1", "v2"], default="v2")
    parser.add_argument("--models", nargs="+", choices=["tfidf", "bm25"], default=["tfidf", "bm25"])
    args = parser.parse_args()

    test_file = SPLITS[args.split]["test"]
    results_dir = SPLITS[args.split]["results"]
    results_dir.mkdir(parents=True, exist_ok=True)

    print(f"Test set: {test_file}")
    test = pd.read_csv(test_file, dtype=str, keep_default_na=False)
    print(f"Test queries: {len(test):,}")
    if "leak_flag" in test.columns:
        print(f"Clean queries (leak_flag = 0): {int((test['leak_flag'] == '0').sum()):,}")
    print()

    all_metrics = []
    for key in args.models:
        model_name, retriever = load_retriever(key)

        start = time.time()
        predictions = rank_all(retriever, test)
        print(f"{model_name}: ranked {len(predictions):,} queries in {time.time() - start:.0f}s")

        metrics = metrics_by_subset(model_name, predictions)
        all_metrics.append(metrics)

        predictions.to_csv(results_dir / f"{key}_predictions.csv", index=False)
        metrics.to_csv(results_dir / f"{key}_metrics.csv", index=False)
        print()

    summary = pd.concat(all_metrics, ignore_index=True)
    summary.to_csv(results_dir / "metrics_summary.csv", index=False)

    print("=" * 78)
    print(f"Results ({args.split} test set)")
    print("=" * 78)
    print(summary.to_string(index=False, float_format=lambda x: f"{x:.4f}"))
    print()
    print(f"Saved to: {results_dir}")


if __name__ == "__main__":
    main()
