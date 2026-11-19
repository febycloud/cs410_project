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


def _validated_ranks(ranks):
    values = [float(rank) for rank in ranks]
    if any(math.isnan(rank) or rank < 1 for rank in values):
        raise ValueError("Ranks must be positive numbers or infinity")
    return values


def _validate_k(k):
    if not isinstance(k, int) or isinstance(k, bool) or k < 1:
        raise ValueError("k must be a positive integer")


def recall_at_k(ranks, k):
    _validate_k(k)
    ranks = _validated_ranks(ranks)
    return sum(rank <= k for rank in ranks) / len(ranks) if ranks else 0.0


def mrr(ranks):
    ranks = _validated_ranks(ranks)
    if not ranks:
        return 0.0
    reciprocals = [
        0.0 if math.isinf(rank) else 1.0 / rank
        for rank in ranks
    ]
    return sum(reciprocals) / len(reciprocals)


def ndcg_at_k(ranks, k):
    _validate_k(k)
    ranks = _validated_ranks(ranks)
    if not ranks:
        return 0.0
    gains = [1.0 / math.log2(rank + 1) if rank <= k else 0.0 for rank in ranks]
    return sum(gains) / len(gains)


def compute_metrics(ranks):
    """All metrics required by docs/model_training.md, in the documented order."""
    return {
        "recall@1": recall_at_k(ranks, 1),
        "recall@3": recall_at_k(ranks, 3),
        "recall@5": recall_at_k(ranks, 5),
        "mrr": mrr(ranks),
        "ndcg@5": ndcg_at_k(ranks, 5),
    }
