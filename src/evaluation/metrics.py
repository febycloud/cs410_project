"""
Ranking metrics for CVE -> CWE retrieval (Checkpoint 3.6).

Each query has exactly one correct CWE, so every metric can be computed from
the rank at which the correct CWE was returned:
    rank = 1 means the correct CWE was the first result
    rank = inf means it was not returned at all

    Recall@k  share of queries whose correct CWE is in the top k
    MRR       mean of 1 / rank (0 when not found)
    nDCG@k    mean of 1 / log2(rank + 1) when rank <= k, else 0
              (with one relevant item, the ideal DCG is 1)
"""
import math

import numpy as np


def recall_at_k(ranks, k):
    ranks = np.asarray(ranks, dtype=float)
    return float(np.mean(ranks <= k)) if len(ranks) else 0.0


def mrr(ranks):
    ranks = np.asarray(ranks, dtype=float)
    return float(np.mean(1.0 / ranks)) if len(ranks) else 0.0  # 1 / inf = 0


def ndcg_at_k(ranks, k):
    ranks = np.asarray(ranks, dtype=float)
    if not len(ranks):
        return 0.0
    gains = [1.0 / math.log2(r + 1) if r <= k else 0.0 for r in ranks]
    return float(np.mean(gains))


def compute_metrics(ranks):
    """All metrics required by docs/model_training.md, in the documented order."""
    return {
        "recall@1": recall_at_k(ranks, 1),
        "recall@3": recall_at_k(ranks, 3),
        "recall@5": recall_at_k(ranks, 5),
        "mrr": mrr(ranks),
        "ndcg@5": ndcg_at_k(ranks, 5),
    }
