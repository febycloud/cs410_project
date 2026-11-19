from pathlib import Path
import os
import time

import pandas as pd

from src.models.tfidf_retriever import TfidfRetriever
from src.models.bm25_retriever import BM25Retriever
from src.models.minilm_retriever import MiniLMRetriever

from src.evaluation.metrics import (
    recall_at_k,
    mrr,
    ndcg_at_k,
)


# ============================================================
# Configuration
# ============================================================

DATA_ROOT = Path(
    os.getenv("DATA_ROOT", "/home/data")
)

TEST_FILE = (
    DATA_ROOT
    / "processed"
    / "test.csv"
)

RESULTS_DIR = (
    DATA_ROOT
    / "results"
)

EXPECTED_CANDIDATE_COUNT = 50

TOP_K = 5


# ============================================================
# Load and validate test dataset
# ============================================================

def load_test_data():
    if not TEST_FILE.exists():
        raise FileNotFoundError(
            f"Test file not found: {TEST_FILE}"
        )

    test_df = pd.read_csv(TEST_FILE)

    required_columns = [
        "cve_id",
        "cve_description",
        "cwe_id",
        "leak_flag",
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in test_df.columns
    ]

    if missing_columns:
        raise ValueError(
            "Test dataset is missing required columns: "
            f"{missing_columns}"
        )

    test_df = test_df.dropna(
        subset=[
            "cve_id",
            "cve_description",
            "cwe_id",
            "leak_flag",
        ]
    ).reset_index(drop=True)

    test_df["cve_id"] = (
        test_df["cve_id"]
        .astype(str)
        .str.strip()
    )

    test_df["cve_description"] = (
        test_df["cve_description"]
        .astype(str)
        .str.strip()
    )

    test_df["cwe_id"] = (
        test_df["cwe_id"]
        .astype(str)
        .str.strip()
    )

    test_df["leak_flag"] = (
        pd.to_numeric(
            test_df["leak_flag"],
            errors="raise",
        )
        .astype(int)
    )

    if (
        test_df["cve_description"]
        .str.len()
        .eq(0)
        .any()
    ):
        raise ValueError(
            "Test dataset contains empty CVE descriptions"
        )

    unique_cwe_count = (
        test_df["cwe_id"]
        .nunique()
    )

    if unique_cwe_count != EXPECTED_CANDIDATE_COUNT:
        raise ValueError(
            f"Expected exactly "
            f"{EXPECTED_CANDIDATE_COUNT} CWE classes "
            f"in test.csv, found {unique_cwe_count}"
        )

    return test_df


# ============================================================
# Convert retrieval result into prediction row
# ============================================================

def build_prediction_row(
    cve_id,
    query,
    ground_truth_cwe,
    leak_flag,
    results,
):
    predicted_ids = [
        result["cwe_id"]
        for result in results
    ]

    ground_truth_rank = None

    for rank, predicted_cwe in enumerate(
        predicted_ids,
        start=1,
    ):
        if predicted_cwe == ground_truth_cwe:
            ground_truth_rank = rank
            break

    output = {
        "cve_id": cve_id,
        "query": query,
        "ground_truth_cwe": ground_truth_cwe,
        "leak_flag": leak_flag,
        "ground_truth_rank": ground_truth_rank,
    }

    for index in range(TOP_K):
        rank = index + 1

        if index < len(results):
            result = results[index]

            output[
                f"rank_{rank}_cwe"
            ] = result["cwe_id"]

            output[
                f"rank_{rank}_score"
            ] = result["score"]

        else:
            output[
                f"rank_{rank}_cwe"
            ] = None

            output[
                f"rank_{rank}_score"
            ] = None

    return output


# ============================================================
# TF-IDF / BM25 evaluation
# ============================================================

def rank_model_one_by_one(
    model_name,
    retriever,
    test_df,
):
    start_time = time.time()

    rows = []

    for row in test_df.itertuples(
        index=False
    ):
        results = retriever.search(
            row.cve_description,
            top_k=TOP_K,
        )

        output = build_prediction_row(
            cve_id=row.cve_id,
            query=row.cve_description,
            ground_truth_cwe=row.cwe_id,
            leak_flag=row.leak_flag,
            results=results,
        )

        rows.append(output)

    elapsed = (
        time.time()
        - start_time
    )

    print(
        f"{model_name}: ranked "
        f"{len(test_df):,} queries "
        f"in {elapsed:.1f}s"
    )

    return pd.DataFrame(rows)


# ============================================================
# MiniLM batch evaluation
# ============================================================

def rank_minilm_batch(
    retriever,
    test_df,
):
    start_time = time.time()

    queries = (
        test_df["cve_description"]
        .tolist()
    )

    all_results = retriever.search_batch(
        queries,
        top_k=TOP_K,
        batch_size=64,
        show_progress_bar=True,
    )

    if len(all_results) != len(test_df):
        raise ValueError(
            "MiniLM batch result count does not match "
            "test query count"
        )

    rows = []

    for row, results in zip(
        test_df.itertuples(
            index=False
        ),
        all_results,
    ):
        output = build_prediction_row(
            cve_id=row.cve_id,
            query=row.cve_description,
            ground_truth_cwe=row.cwe_id,
            leak_flag=row.leak_flag,
            results=results,
        )

        rows.append(output)

    elapsed = (
        time.time()
        - start_time
    )

    print(
        f"MiniLM: ranked "
        f"{len(test_df):,} queries "
        f"in {elapsed:.1f}s"
    )

    return pd.DataFrame(rows)


# ============================================================
# Metrics
# ============================================================

def extract_ranks(predictions_df):
    ranks = []

    for value in predictions_df[
        "ground_truth_rank"
    ]:
        if pd.isna(value):
            ranks.append(None)
        else:
            ranks.append(int(value))

    return ranks


def compute_subset_metrics(
    model_name,
    subset_name,
    predictions_df,
):
    ranks = extract_ranks(
        predictions_df
    )

    return {
        "model": model_name,
        "subset": subset_name,
        "queries": len(predictions_df),
        "recall@1": recall_at_k(
            ranks,
            1,
        ),
        "recall@3": recall_at_k(
            ranks,
            3,
        ),
        "recall@5": recall_at_k(
            ranks,
            5,
        ),
        "mrr": mrr(ranks),
        "ndcg@5": ndcg_at_k(
            ranks,
            5,
        ),
    }


def evaluate_subsets(
    model_name,
    predictions_df,
):
    all_metrics = (
        compute_subset_metrics(
            model_name=model_name,
            subset_name="all",
            predictions_df=predictions_df,
        )
    )

    clean_df = predictions_df[
        predictions_df["leak_flag"] == 0
    ].copy()

    clean_metrics = (
        compute_subset_metrics(
            model_name=model_name,
            subset_name="clean",
            predictions_df=clean_df,
        )
    )

    return pd.DataFrame(
        [
            all_metrics,
            clean_metrics,
        ]
    )


# ============================================================
# Save results
# ============================================================

def save_results(
    model_key,
    predictions_df,
    metrics_df,
):
    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    predictions_file = (
        RESULTS_DIR
        / f"{model_key}_predictions.csv"
    )

    metrics_file = (
        RESULTS_DIR
        / f"{model_key}_metrics.csv"
    )

    predictions_df.to_csv(
        predictions_file,
        index=False,
        encoding="utf-8",
    )

    metrics_df.to_csv(
        metrics_file,
        index=False,
        encoding="utf-8",
    )

    print(
        f"Saved predictions: "
        f"{predictions_file}"
    )

    print(
        f"Saved metrics: "
        f"{metrics_file}"
    )


# ============================================================
# Candidate validation
# ============================================================

def validate_retriever(
    model_name,
    retriever,
):
    candidate_count = (
        retriever.get_candidate_count()
    )

    if (
        candidate_count
        != EXPECTED_CANDIDATE_COUNT
    ):
        raise ValueError(
            f"{model_name} expected "
            f"{EXPECTED_CANDIDATE_COUNT} candidates, "
            f"got {candidate_count}"
        )

    print(
        f"{model_name} candidate count: "
        f"{candidate_count}"
    )


# ============================================================
# Main
# ============================================================

def main():
    test_df = load_test_data()

    print(
        f"Test set: {TEST_FILE}"
    )

    print(
        f"Test queries: "
        f"{len(test_df):,}"
    )

    clean_count = int(
        (
            test_df["leak_flag"]
            == 0
        ).sum()
    )

    print(
        "Clean queries "
        "(leak_flag = 0): "
        f"{clean_count:,}"
    )

    print()

    all_metrics = []

    # ========================================================
    # TF-IDF
    # ========================================================

    tfidf = TfidfRetriever()

    validate_retriever(
        "TF-IDF",
        tfidf,
    )

    tfidf_predictions = (
        rank_model_one_by_one(
            model_name="TF-IDF",
            retriever=tfidf,
            test_df=test_df,
        )
    )

    tfidf_metrics = evaluate_subsets(
        model_name="TF-IDF",
        predictions_df=tfidf_predictions,
    )

    save_results(
        model_key="tfidf",
        predictions_df=tfidf_predictions,
        metrics_df=tfidf_metrics,
    )

    all_metrics.append(
        tfidf_metrics
    )

    print()

    # ========================================================
    # BM25
    # ========================================================

    bm25 = BM25Retriever()

    validate_retriever(
        "BM25",
        bm25,
    )

    bm25_predictions = (
        rank_model_one_by_one(
            model_name="BM25",
            retriever=bm25,
            test_df=test_df,
        )
    )

    bm25_metrics = evaluate_subsets(
        model_name="BM25",
        predictions_df=bm25_predictions,
    )

    save_results(
        model_key="bm25",
        predictions_df=bm25_predictions,
        metrics_df=bm25_metrics,
    )

    all_metrics.append(
        bm25_metrics
    )

    print()

    # ========================================================
    # MiniLM
    # ========================================================

    minilm = MiniLMRetriever()

    validate_retriever(
        "MiniLM",
        minilm,
    )

    minilm_predictions = (
        rank_minilm_batch(
            retriever=minilm,
            test_df=test_df,
        )
    )

    minilm_metrics = evaluate_subsets(
        model_name="MiniLM",
        predictions_df=minilm_predictions,
    )

    save_results(
        model_key="minilm",
        predictions_df=minilm_predictions,
        metrics_df=minilm_metrics,
    )

    all_metrics.append(
        minilm_metrics
    )

    # ========================================================
    # Combined comparison
    # ========================================================

    comparison_df = pd.concat(
        all_metrics,
        ignore_index=True,
    )

    comparison_file = (
        RESULTS_DIR
        / "model_comparison.csv"
    )

    comparison_df.to_csv(
        comparison_file,
        index=False,
        encoding="utf-8",
    )

    print()
    print("=" * 90)
    print("MODEL COMPARISON")
    print("=" * 90)

    print(
        comparison_df.to_string(
            index=False
        )
    )

    print()
    print(
        f"Saved comparison: "
        f"{comparison_file}"
    )


if __name__ == "__main__":
    main()