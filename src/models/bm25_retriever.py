from pathlib import Path
import re

import numpy as np
import pandas as pd
from rank_bm25 import BM25Okapi


DATA_ROOT = Path("/home/data")

CWE_FILE = DATA_ROOT / "processed" / "cwe_clean.csv"
TOP50_FILE = DATA_ROOT / "processed" / "cve_cwe_top50.csv"


def tokenize(text: str):
    """
    Simple tokenizer for BM25.

    Converts text to lowercase and extracts words/numbers.
    """

    if not isinstance(text, str):
        return []

    return re.findall(
        r"\b\w+\b",
        text.lower(),
    )


class BM25Retriever:
    def __init__(
        self,
        cwe_file=CWE_FILE,
        candidate_file=TOP50_FILE,
    ):
        """
        BM25 based CWE retriever.

        Parameters
        ----------
        cwe_file:
            Path to cleaned CWE dataset.

        candidate_file:
            Path to dataset used to define allowed CWE candidates.
            By default, this uses the Top 50 CWE dataset.
        """

        self.cwe_file = Path(cwe_file)
        self.candidate_file = Path(candidate_file)

        self._load_data()
        self._build_index()

    def _load_data(self):
        """
        Load CWE definitions and restrict the candidate corpus
        to CWE classes included in the Top 50 dataset.
        """

        if not self.cwe_file.exists():
            raise FileNotFoundError(
                f"CWE file not found: {self.cwe_file}"
            )

        if not self.candidate_file.exists():
            raise FileNotFoundError(
                f"Candidate file not found: {self.candidate_file}"
            )

        self.cwe_df = pd.read_csv(
            self.cwe_file
        )

        candidate_df = pd.read_csv(
            self.candidate_file
        )

        required_cwe_columns = [
            "cwe_id",
            "name",
            "search_text",
        ]

        missing_cwe_columns = [
            column
            for column in required_cwe_columns
            if column not in self.cwe_df.columns
        ]

        if missing_cwe_columns:
            raise ValueError(
                f"Missing required columns in CWE file: "
                f"{missing_cwe_columns}"
            )

        if "cwe_id" not in candidate_df.columns:
            raise ValueError(
                "Candidate dataset must contain a 'cwe_id' column"
            )

        allowed_cwe_ids = set(
            candidate_df["cwe_id"]
            .dropna()
            .astype(str)
            .unique()
        )

        self.cwe_df = self.cwe_df[
            self.cwe_df["cwe_id"]
            .astype(str)
            .isin(allowed_cwe_ids)
        ].copy()

        self.cwe_df = self.cwe_df.dropna(
            subset=[
                "cwe_id",
                "name",
                "search_text",
            ]
        )

        self.cwe_df["cwe_id"] = (
            self.cwe_df["cwe_id"]
            .astype(str)
            .str.strip()
        )

        self.cwe_df["name"] = (
            self.cwe_df["name"]
            .astype(str)
            .str.strip()
        )

        self.cwe_df["search_text"] = (
            self.cwe_df["search_text"]
            .astype(str)
            .str.strip()
        )

        self.cwe_df = self.cwe_df[
            self.cwe_df["search_text"].str.len() > 0
        ]

        self.cwe_df = (
            self.cwe_df
            .drop_duplicates(
                subset=["cwe_id"]
            )
            .reset_index(drop=True)
        )

        if self.cwe_df.empty:
            raise ValueError(
                "No valid CWE candidates were loaded"
            )

        print(
            f"Loaded {len(self.cwe_df)} CWE candidates"
        )

    def _build_index(self):
        """
        Build BM25 index from CWE search text.
        """

        self.tokenized_corpus = [
            tokenize(text)
            for text in self.cwe_df["search_text"]
        ]

        self.bm25 = BM25Okapi(
            self.tokenized_corpus
        )

        print(
            f"BM25 index built with "
            f"{len(self.tokenized_corpus)} documents"
        )

    def search(
        self,
        query: str,
        top_k: int = 5,
    ):
        """
        Retrieve the Top-K CWE categories for a query.

        Parameters
        ----------
        query:
            Vulnerability description.

        top_k:
            Number of CWE results to return.

        Returns
        -------
        list[dict]
            Ranked CWE results.
        """

        if not isinstance(query, str):
            raise ValueError(
                "Query must be a string"
            )

        query = query.strip()

        if not query:
            raise ValueError(
                "Query cannot be empty"
            )

        if not isinstance(top_k, int):
            raise ValueError(
                "top_k must be an integer"
            )

        if top_k < 1:
            raise ValueError(
                "top_k must be at least 1"
            )

        top_k = min(
            top_k,
            len(self.cwe_df),
        )

        query_tokens = tokenize(
            query
        )

        if not query_tokens:
            raise ValueError(
                "Query does not contain valid tokens"
            )

        scores = self.bm25.get_scores(
            query_tokens
        )

        top_indices = np.argsort(
            scores
        )[::-1][:top_k]

        results = []

        for rank, index in enumerate(
            top_indices,
            start=1,
        ):
            row = self.cwe_df.iloc[
                index
            ]

            results.append(
                {
                    "rank": rank,
                    "cwe_id": row["cwe_id"],
                    "name": row["name"],
                    "score": float(
                        scores[index]
                    ),
                }
            )

        return results

    def get_candidate_count(self):
        """
        Return the number of CWE candidates.
        """

        return len(
            self.cwe_df
        )


def main():
    retriever = BM25Retriever()

    print()
    print(
        "Candidate CWE count:",
        retriever.get_candidate_count(),
    )

    print()

    test_queries = [
        (
            "Path Traversal",
            "An attacker can use ../ sequences "
            "to access files outside the intended directory.",
        ),
        (
            "SQL Injection",
            "Unsanitized user input is directly "
            "inserted into a SQL query.",
        ),
        (
            "Cross-site Scripting",
            "User controlled input is rendered "
            "in a web page without proper escaping.",
        ),
    ]

    for title, query in test_queries:

        print(
            "=" * 70
        )

        print(
            title
        )

        print(
            "=" * 70
        )

        print(
            "Query:"
        )

        print(
            query
        )

        print()

        results = retriever.search(
            query=query,
            top_k=5,
        )

        for result in results:

            print(
                f"{result['rank']}. "
                f"{result['cwe_id']} | "
                f"{result['name']} | "
                f"score={result['score']:.4f}"
            )

        print()


if __name__ == "__main__":
    main()