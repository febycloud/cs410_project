from pathlib import Path
import re

import numpy as np
import pandas as pd
import torch
from sentence_transformers import SentenceTransformer


# ============================================================
# Paths
# ============================================================

DATA_ROOT = Path("/home/data")

PROCESSED_DIR = DATA_ROOT / "processed"
EMBEDDING_DIR = DATA_ROOT / "embeddings" / "minilm"

CWE_FILE = PROCESSED_DIR / "cwe_clean.csv"
TOP50_FILE = PROCESSED_DIR / "cve_cwe_top50.csv"

CWE_EMBEDDING_FILE = EMBEDDING_DIR / "cwe_embeddings.npy"
CWE_METADATA_FILE = EMBEDDING_DIR / "cwe_metadata.csv"


# ============================================================
# Model
# ============================================================

DEFAULT_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def remove_cwe_ids(text: str) -> str:
    """
    Remove explicit CWE IDs from user queries.

    Example:
        "This vulnerability is CWE-79 XSS"
        ->
        "This vulnerability is XSS"

    This reduces direct label leakage.
    """

    if not isinstance(text, str):
        return ""

    text = re.sub(
        r"\bCWE-\d+\b",
        "",
        text,
        flags=re.IGNORECASE,
    )

    return " ".join(text.split())


class MiniLMRetriever:
    def __init__(
        self,
        cwe_file=CWE_FILE,
        candidate_file=TOP50_FILE,
        model_name=DEFAULT_MODEL_NAME,
        use_saved_embeddings=True,
    ):
        """
        Semantic CWE retriever using MiniLM embeddings.

        Parameters
        ----------
        cwe_file:
            Clean CWE definitions.

        candidate_file:
            Dataset used to determine allowed CWE candidates.
            Default: Top 50 CWE dataset.

        model_name:
            SentenceTransformer model.

        use_saved_embeddings:
            Load previously generated CWE embeddings if available.
        """

        self.cwe_file = Path(cwe_file)
        self.candidate_file = Path(candidate_file)

        self.model_name = model_name
        self.use_saved_embeddings = use_saved_embeddings

        self.device = self._get_device()

        print(f"Using device: {self.device}")

        self._load_data()
        self._load_model()
        self._prepare_embeddings()

    # ========================================================
    # Device
    # ========================================================

    def _get_device(self):
        if torch.cuda.is_available():
            return "cuda"

        if (
            hasattr(torch.backends, "mps")
            and torch.backends.mps.is_available()
        ):
            return "mps"

        return "cpu"

    # ========================================================
    # Load CWE corpus
    # ========================================================

    def _load_data(self):
        if not self.cwe_file.exists():
            raise FileNotFoundError(
                f"CWE file not found: {self.cwe_file}"
            )

        if not self.candidate_file.exists():
            raise FileNotFoundError(
                f"Candidate file not found: {self.candidate_file}"
            )

        cwe_df = pd.read_csv(self.cwe_file)
        candidate_df = pd.read_csv(self.candidate_file)

        required_columns = [
            "cwe_id",
            "name",
            "search_text",
        ]

        missing = [
            column
            for column in required_columns
            if column not in cwe_df.columns
        ]

        if missing:
            raise ValueError(
                f"Missing required columns in CWE dataset: {missing}"
            )

        if "cwe_id" not in candidate_df.columns:
            raise ValueError(
                "Candidate dataset must contain a cwe_id column"
            )

        # Get the Top 50 CWE candidate IDs
        allowed_cwe_ids = set(
            candidate_df["cwe_id"]
            .dropna()
            .astype(str)
            .str.strip()
            .unique()
        )

        # Restrict CWE corpus to Top 50
        cwe_df = cwe_df[
            cwe_df["cwe_id"]
            .astype(str)
            .str.strip()
            .isin(allowed_cwe_ids)
        ].copy()

        # Remove missing values
        cwe_df = cwe_df.dropna(
            subset=[
                "cwe_id",
                "name",
                "search_text",
            ]
        )

        # Normalize fields
        cwe_df["cwe_id"] = (
            cwe_df["cwe_id"]
            .astype(str)
            .str.strip()
        )

        cwe_df["name"] = (
            cwe_df["name"]
            .astype(str)
            .str.strip()
        )

        cwe_df["search_text"] = (
            cwe_df["search_text"]
            .astype(str)
            .str.strip()
        )

        # Remove empty search text
        cwe_df = cwe_df[
            cwe_df["search_text"].str.len() > 0
        ]

        # One document per CWE
        cwe_df = (
            cwe_df
            .drop_duplicates(subset=["cwe_id"])
            .sort_values("cwe_id")
            .reset_index(drop=True)
        )

        if cwe_df.empty:
            raise ValueError(
                "No valid CWE candidates were loaded"
            )

        self.cwe_df = cwe_df

        print(
            f"Loaded {len(self.cwe_df)} CWE candidates"
        )

    # ========================================================
    # Load MiniLM
    # ========================================================

    def _load_model(self):
        print(
            f"Loading model: {self.model_name}"
        )

        self.model = SentenceTransformer(
            self.model_name,
            device=self.device,
        )

    # ========================================================
    # CWE embeddings
    # ========================================================

    def _prepare_embeddings(self):
        EMBEDDING_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        if (
            self.use_saved_embeddings
            and CWE_EMBEDDING_FILE.exists()
            and CWE_METADATA_FILE.exists()
        ):
            metadata = pd.read_csv(
                CWE_METADATA_FILE
            )

            if "cwe_id" in metadata.columns:
                saved_ids = (
                    metadata["cwe_id"]
                    .astype(str)
                    .tolist()
                )

                current_ids = (
                    self.cwe_df["cwe_id"]
                    .astype(str)
                    .tolist()
                )

                if saved_ids == current_ids:
                    embeddings = np.load(
                        CWE_EMBEDDING_FILE
                    )

                    if len(embeddings) == len(self.cwe_df):
                        self.cwe_embeddings = embeddings

                        print(
                            "Loaded saved CWE embeddings"
                        )

                        print(
                            f"Embedding shape: "
                            f"{self.cwe_embeddings.shape}"
                        )

                        return

            print(
                "Saved embeddings do not match "
                "the current CWE candidate set."
            )

            print(
                "Regenerating embeddings..."
            )

        self._generate_embeddings()

    def _generate_embeddings(self):
        print(
            "Generating CWE embeddings..."
        )

        documents = (
            self.cwe_df["search_text"]
            .tolist()
        )

        self.cwe_embeddings = self.model.encode(
            documents,
            batch_size=32,
            show_progress_bar=True,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )

        np.save(
            CWE_EMBEDDING_FILE,
            self.cwe_embeddings,
        )

        self.cwe_df[
            [
                "cwe_id",
                "name",
            ]
        ].to_csv(
            CWE_METADATA_FILE,
            index=False,
            encoding="utf-8",
        )

        print(
            f"Saved embeddings to: "
            f"{CWE_EMBEDDING_FILE}"
        )

        print(
            f"Saved metadata to: "
            f"{CWE_METADATA_FILE}"
        )

        print(
            f"Embedding shape: "
            f"{self.cwe_embeddings.shape}"
        )

    # ========================================================
    # Search
    # ========================================================

    def search(
        self,
        query: str,
        top_k: int = 5,
    ):
        """
        Retrieve the most relevant CWE categories.

        Returns
        -------
        list[dict]

        Example:
        [
            {
                "rank": 1,
                "cwe_id": "CWE-22",
                "name": "Path Traversal",
                "score": 0.82
            }
        ]
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

        # Remove explicit CWE labels from query
        query = remove_cwe_ids(query)

        if not query:
            raise ValueError(
                "Query is empty after preprocessing"
            )

        query_embedding = self.model.encode(
            query,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )

        # Embeddings are normalized,
        # therefore dot product = cosine similarity
        scores = np.dot(
            self.cwe_embeddings,
            query_embedding,
        )

        top_indices = np.argsort(
            scores
        )[::-1][:top_k]

        results = []

        for rank, index in enumerate(
            top_indices,
            start=1,
        ):
            row = self.cwe_df.iloc[index]

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

    # ========================================================
    # Utility
    # ========================================================

    def get_candidate_count(self):
        return len(self.cwe_df)


# ============================================================
# Manual test
# ============================================================

def main():
    retriever = MiniLMRetriever()

    print()
    print(
        "Candidate CWE count:",
        retriever.get_candidate_count(),
    )

    test_queries = [
        (
            "Path Traversal",
            (
                "An attacker can use ../ sequences "
                "to access files outside the intended directory."
            ),
        ),
        (
            "SQL Injection",
            (
                "Unsanitized user input is directly "
                "inserted into a SQL query."
            ),
        ),
        (
            "Cross-site Scripting",
            (
                "User controlled input is rendered "
                "in a web page without proper escaping."
            ),
        ),
    ]

    for title, query in test_queries:
        print()
        print("=" * 70)
        print(title)
        print("=" * 70)

        print("Query:")
        print(query)
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


if __name__ == "__main__":
    main()