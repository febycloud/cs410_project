import math


def _validated_ranks(ranks):
    """
    Validate rank values.

    A rank represents the position of the ground-truth CWE
    in the retrieved results.

    Valid examples:
        1
        2
        5

    A missing result can be represented as:
        None
        NaN

    Missing results are converted to None and contribute
    zero to Recall, MRR, and nDCG.
    """

    validated = []

    for rank in ranks:
        # Retrieval miss
        if rank is None:
            validated.append(None)
            continue

        try:
            value = float(rank)
        except (TypeError, ValueError):
            raise ValueError(
                f"Invalid rank value: {rank}"
            )

        # pandas / numpy NaN
        if math.isnan(value):
            validated.append(None)
            continue

        # Infinite ranks should not occur
        if math.isinf(value):
            raise ValueError(
                f"Rank must be finite: {rank}"
            )

        if value < 1:
            raise ValueError(
                f"Rank must be >= 1: {rank}"
            )

        if not value.is_integer():
            raise ValueError(
                f"Rank must be an integer: {rank}"
            )

        validated.append(
            int(value)
        )

    return validated


def _validate_k(k):
    """
    Validate cutoff K.
    """

    if not isinstance(k, int):
        raise ValueError(
            "k must be an integer"
        )

    if k < 1:
        raise ValueError(
            "k must be >= 1"
        )

    return k


def recall_at_k(ranks, k):
    """
    Recall@K for a single-label retrieval task.

    For each CVE there is one ground-truth CWE.

    A query counts as a hit when the ground-truth CWE
    appears within the Top-K results.

    Misses (None) contribute 0.
    """

    ranks = _validated_ranks(ranks)
    k = _validate_k(k)

    if not ranks:
        return 0.0

    hits = sum(
        1
        for rank in ranks
        if rank is not None
        and rank <= k
    )

    return hits / len(ranks)


def mrr(ranks):
    """
    Mean Reciprocal Rank.

    Reciprocal rank:

        rank 1 -> 1.0
        rank 2 -> 0.5
        rank 3 -> 0.333...
        miss   -> 0.0
    """

    ranks = _validated_ranks(ranks)

    if not ranks:
        return 0.0

    reciprocal_ranks = [
        (
            1.0 / rank
            if rank is not None
            else 0.0
        )
        for rank in ranks
    ]

    return (
        sum(reciprocal_ranks)
        / len(reciprocal_ranks)
    )


def ndcg_at_k(ranks, k):
    """
    nDCG@K for a single relevant CWE per query.

    Since there is exactly one relevant CWE,
    ideal DCG is 1.0.

    Therefore:

        rank 1 -> 1.0
        rank 2 -> 1 / log2(3)
        rank 3 -> 1 / log2(4)
        ...
        rank > K -> 0
        miss -> 0
    """

    ranks = _validated_ranks(ranks)
    k = _validate_k(k)

    if not ranks:
        return 0.0

    scores = []

    for rank in ranks:
        if (
            rank is None
            or rank > k
        ):
            scores.append(0.0)
            continue

        score = (
            1.0
            / math.log2(rank + 1)
        )

        scores.append(score)

    return (
        sum(scores)
        / len(scores)
    )


def compute_metrics(ranks):
    """
    Compute the standard evaluation metrics
    used in this project.
    """

    return {
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