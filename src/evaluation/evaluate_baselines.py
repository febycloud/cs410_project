"""
Evaluate the TF-IDF, BM25, and MiniLM retrievers.

For every CVE in the test set:
    query        = cve_description
    ground truth = cwe_id
Each retriever ranks all candidate CWEs; the rank of the correct CWE gives
Recall@1/3/5, MRR and nDCG@5 (see metrics.py).

Leakage-aware reporting:
    The official test set has a leak_flag column.
    Metrics are reported for two subsets:
        all     every test row
        clean   leak_flag == 0   <- the honest number to compare models on

Official test set:
    /home/data/processed/test.csv
Results:
    /home/data/results/

Outputs (in the results folder above):
    <model>_metrics.csv       one row per subset
    <model>_predictions.csv   top-5 results for every CVE
    metrics_summary.csv       all requested models together

Usage (from the project root, with .venv activated):
    python -m src.evaluation.evaluate_baselines
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

TEST_FILE = PROCESSED / "test.csv"
RESULTS_DIR = DATA_ROOT / "results"

METRIC_COLUMNS = ["recall@1", "recall@3", "recall@5", "mrr", "ndcg@5"]
TOP_N_SAVED = 5  # predictions file keeps the top 5 results per query


def load_retriever(name):
    """Import lazily so optional model dependencies are needed only when used."""
    if name == "tfidf":
        from src.models.tfidf_retriever import TfidfRetriever
        return "TF-IDF", TfidfRetriever(cwe_file=CWE_FILE, candidate_file=CANDIDATE_FILE)
    if name == "bm25":
        from src.models.bm25_retriever import BM25Retriever
        return "BM25", BM25Retriever(cwe_file=CWE_FILE, candidate_file=CANDIDATE_FILE)
    if name == "minilm":
        from src.models.minilm_retriever import MiniLMRetriever
        return "MiniLM", MiniLMRetriever(cwe_file=CWE_FILE, candidate_file=CANDIDATE_FILE)
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
    """Metrics for all rows and exactly the leak_flag == 0 rows."""
    if "leak_flag" not in predictions.columns:
        raise ValueError("Official test data must contain a leak_flag column")

    flag = pd.to_numeric(predictions["leak_flag"], errors="raise")
    clean = predictions[flag == 0]
    if clean.empty:
        raise ValueError("Official test data contains no clean (leak_flag == 0) rows")
    subsets = [
        ("all", predictions),
        ("clean", clean),
    ]

    out = []
    for subset, part in subsets:
        m = compute_metrics(part["ground_truth_rank"].to_numpy())
        out.append({"model": model_name, "subset": subset, "n": len(part), **m})
    return pd.DataFrame(out)[["model", "subset", "n"] + METRIC_COLUMNS]


def main():
    parser = argparse.ArgumentParser(description="Evaluate CVE-to-CWE retrievers")
    parser.add_argument(
        "--models",
        nargs="+",
        choices=["tfidf", "bm25", "minilm"],
        default=["tfidf", "bm25", "minilm"],
    )
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Test set: {TEST_FILE}")
    test = pd.read_csv(TEST_FILE, dtype=str, keep_default_na=False)
    required = {"cve_id", "cve_description", "cwe_id", "leak_flag"}
    missing = sorted(required - set(test.columns))
    if missing:
        raise ValueError(f"Official test data is missing columns: {missing}")

    candidate_df = pd.read_csv(CANDIDATE_FILE, dtype=str, keep_default_na=False)
    if "cwe_id" not in candidate_df.columns:
        raise ValueError("Candidate data is missing the cwe_id column")
    candidate_ids = set(candidate_df["cwe_id"].str.strip()) - {""}
    if len(candidate_ids) != 50:
        raise ValueError(
            f"Expected exactly 50 candidate CWE IDs, found {len(candidate_ids)}"
        )
    test_ids = set(test["cwe_id"].str.strip())
    outside_candidates = sorted(test_ids - candidate_ids)
    if outside_candidates:
        raise ValueError(
            "Official test data contains labels outside the Top-50 candidate set: "
            f"{outside_candidates}"
        )
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

        predictions.to_csv(RESULTS_DIR / f"{key}_predictions.csv", index=False)
        metrics.to_csv(RESULTS_DIR / f"{key}_metrics.csv", index=False)
        print()

    summary = pd.concat(all_metrics, ignore_index=True)
    summary.to_csv(RESULTS_DIR / "metrics_summary.csv", index=False)

    print("=" * 78)
    print("Results (official test set)")
    print("=" * 78)
    print(summary.to_string(index=False, float_format=lambda x: f"{x:.4f}"))
    print()
    print(f"Saved to: {RESULTS_DIR}")


if __name__ == "__main__":
    main()
