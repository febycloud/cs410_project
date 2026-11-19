from pathlib import Path
import os

import numpy as np
import pandas as pd
import torch
from sentence_transformers import SentenceTransformer

try:
    from .query_preprocessing import remove_cwe_ids
except ImportError:
    from query_preprocessing import remove_cwe_ids


DATA_ROOT = Path(
    os.getenv("DATA_ROOT", "/home/data")
)

PROCESSED_DIR = DATA_ROOT / "processed"
EMBEDDING_DIR = DATA_ROOT / "embeddings" / "minilm"

CWE_FILE = PROCESSED_DIR / "cwe_clean.csv"
TOP50_FILE = PROCESSED_DIR / "cve_cwe_top50.csv"

CWE_EMBEDDING_FILE = (
    EMBEDDING_DIR / "cwe_embeddings.npy"
)

CWE_METADATA_FILE = (
    EMBEDDING_DIR / "cwe_metadata.csv"
)

DEFAULT_MODEL_NAME = (
    "sentence-transformers/all-MiniLM-L6-v2"
)


class MiniLMRetriever:
    def __init__(
        self,
        cwe_file=CWE_FILE,
        candidate_file=TOP50_FILE,
        model_name=DEFAULT_MODEL_NAME,
        use_saved_embeddings=True,
    ):
        self.cwe_file = Path(cwe_file)
        self.candidate_file = Path(candidate_file)
        self.model_name = model_name
        self.use_saved_embeddings = use_saved_embeddings

        self.device = self._get_device()

        print(
            f"Using device: {self.device}"
        )

        self._load_data()
        self._load_model()
        self._prepare_embeddings()

    # =========================================================
    # Device
    # =========================================================

    def _get_device(self):
        if torch.cuda.is_available():
            return "cuda"

        if (
            hasattr(torch.backends, "mps")
            and torch.backends.mps.is_available()
        ):
            return "mps"

        return "cpu"

    # =========================================================
    # Data
    # =========================================================

    def _load_data(self):
        if not self.cwe_file.exists():
            raise FileNotFoundError(
                f"CWE file not found: "
                f"{self.cwe_file}"
            )

        if not self.candidate_file.exists():
            raise FileNotFoundError(
                f"Candidate file not found: "
                f"{self.candidate_file}"
            )

        cwe_df = pd.read_csv(
            self.cwe_file
        )

        candidate_df = pd.read_csv(
            self.candidate_file
        )

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
                "Missing required CWE columns: "
                f"{missing}"
            )

        if "cwe_id" not in candidate_df.columns:
            raise ValueError(
                "Candidate dataset must contain "
                "'cwe_id'"
            )

        allowed_cwe_ids = set(
            candidate_df["cwe_id"]
            .dropna()
            .astype(str)
            .str.strip()
            .unique()
        )

        if not allowed_cwe_ids:
            raise ValueError(
                "Candidate dataset contains "
                "no CWE IDs"
            )

        cwe_df["cwe_id"] = (
            cwe_df["cwe_id"]
            .astype(str)
            .str.strip()
        )

        cwe_df = cwe_df[
            cwe_df["cwe_id"].isin(
                allowed_cwe_ids
            )
        ].copy()

        cwe_df = cwe_df.dropna(
            subset=[
                "cwe_id",
                "name",
                "search_text",
            ]
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

        cwe_df = cwe_df[
            cwe_df["search_text"].str.len() > 0
        ]

        cwe_df = (
            cwe_df
            .drop_duplicates(
                subset=["cwe_id"]
            )
            .sort_values("cwe_id")
            .reset_index(drop=True)
        )

        missing_candidates = (
            allowed_cwe_ids
            - set(cwe_df["cwe_id"])
        )

        if missing_candidates:
            raise ValueError(
                "CWE definitions are missing "
                "valid search documents for: "
                f"{sorted(missing_candidates)}"
            )

        if len(cwe_df) != 50:
            raise ValueError(
                "Expected exactly 50 CWE "
                f"candidates, got {len(cwe_df)}"
            )

        self.cwe_df = cwe_df

        print(
            f"Loaded {len(self.cwe_df)} "
            "CWE candidates"
        )

    # =========================================================
    # Model
    # =========================================================

    def _load_model(self):
        print(
            f"Loading model: {self.model_name}"
        )

        self.model = SentenceTransformer(
            self.model_name,
            device=self.device,
        )

    # =========================================================
    # Embeddings
    # =========================================================

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
            if self._try_load_embeddings():
                return

            print(
                "Saved embeddings do not match "
                "the current CWE candidate set."
            )

            print(
                "Regenerating embeddings..."
            )

        self._generate_embeddings()

    def _try_load_embeddings(self):
        try:
            metadata = pd.read_csv(
                CWE_METADATA_FILE
            )

            embeddings = np.load(
                CWE_EMBEDDING_FILE
            )

        except Exception:
            return False

        required_metadata = [
            "cwe_id",
            "name",
            "search_text",
            "model_name",
        ]

        if any(
            column not in metadata.columns
            for column in required_metadata
        ):
            return False

        current_metadata = (
            self.cwe_df[
                [
                    "cwe_id",
                    "name",
                    "search_text",
                ]
            ]
            .copy()
        )

        current_metadata[
            "model_name"
        ] = self.model_name

        metadata = metadata[
            required_metadata
        ].reset_index(drop=True)

        current_metadata = (
            current_metadata[
                required_metadata
            ]
            .reset_index(drop=True)
        )

        if not metadata.equals(
            current_metadata
        ):
            return False

        expected_dim = (
            self.model.get_embedding_dimension()
        )

        expected_shape = (
            len(self.cwe_df),
            expected_dim,
        )

        if embeddings.shape != expected_shape:
            return False

        if not np.isfinite(
            embeddings
        ).all():
            return False

        norms = np.linalg.norm(
            embeddings,
            axis=1,
        )

        if not np.allclose(
            norms,
            1.0,
            atol=1e-3,
        ):
            return False

        self.cwe_embeddings = (
            embeddings.astype(
                np.float32,
                copy=False,
            )
        )

        print(
            "Loaded saved CWE embeddings"
        )

        print(
            f"Embedding shape: "
            f"{self.cwe_embeddings.shape}"
        )

        return True

    def _generate_embeddings(self):
        print(
            "Generating CWE embeddings..."
        )

        documents = (
            self.cwe_df["search_text"]
            .tolist()
        )

        embeddings = self.model.encode(
            documents,
            batch_size=32,
            show_progress_bar=True,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )

        self.cwe_embeddings = (
            embeddings.astype(
                np.float32,
                copy=False,
            )
        )

        np.save(
            CWE_EMBEDDING_FILE,
            self.cwe_embeddings,
        )

        metadata = self.cwe_df[
            [
                "cwe_id",
                "name",
                "search_text",
            ]
        ].copy()

        metadata[
            "model_name"
        ] = self.model_name

        metadata.to_csv(
            CWE_METADATA_FILE,
            index=False,
            encoding="utf-8",
        )

        print(
            "Saved embeddings to:"
        )
        print(
            CWE_EMBEDDING_FILE
        )

        print(
            "Saved metadata to:"
        )
        print(
            CWE_METADATA_FILE
        )

        print(
            f"Embedding shape: "
            f"{self.cwe_embeddings.shape}"
        )

    # =========================================================
    # Single-query search
    # Used by API / manual testing
    # =========================================================

    def search(
        self,
        query: str,
        top_k: int = 5,
    ):
        if not isinstance(
            query,
            str,
        ):
            raise ValueError(
                "Query must be a string"
            )

        query = remove_cwe_ids(
            query.strip()
        )

        if not query:
            raise ValueError(
                "Query cannot be empty"
            )

        if not isinstance(
            top_k,
            int,
        ):
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

        query_embedding = (
            self.model.encode(
                query,
                convert_to_numpy=True,
                normalize_embeddings=True,
            )
        )

        scores = np.dot(
            self.cwe_embeddings,
            query_embedding,
        )

        top_indices = (
            np.argsort(scores)
            [::-1][:top_k]
        )

        return self._format_results(
            scores,
            top_indices,
        )

    # =========================================================
    # Batch search
    # Used by evaluation
    # =========================================================

    def search_batch(
        self,
        queries,
        top_k=5,
        batch_size=64,
        show_progress_bar=True,
    ):
        """
        Efficiently rank many CVE queries.

        Returns one Top-K result list
        for each input query.
        """

        if top_k < 1:
            raise ValueError(
                "top_k must be at least 1"
            )

        top_k = min(
            top_k,
            len(self.cwe_df),
        )

        cleaned_queries = []

        for query in queries:
            if not isinstance(
                query,
                str,
            ):
                raise ValueError(
                    "Every query must be a string"
                )

            cleaned = remove_cwe_ids(
                query.strip()
            )

            if not cleaned:
                raise ValueError(
                    "Query cannot be empty "
                    "after preprocessing"
                )

            cleaned_queries.append(
                cleaned
            )

        query_embeddings = (
            self.model.encode(
                cleaned_queries,
                batch_size=batch_size,
                show_progress_bar=(
                    show_progress_bar
                ),
                convert_to_numpy=True,
                normalize_embeddings=True,
            )
        )

        query_embeddings = (
            query_embeddings.astype(
                np.float32,
                copy=False,
            )
        )

        # Shape:
        # queries x CWE candidates
        score_matrix = np.matmul(
            query_embeddings,
            self.cwe_embeddings.T,
        )

        # Only 50 candidates, so argsort
        # is perfectly fine here.
        top_indices_matrix = (
            np.argsort(
                score_matrix,
                axis=1,
            )[:, ::-1][:, :top_k]
        )

        all_results = []

        for row_index, indices in enumerate(
            top_indices_matrix
        ):
            scores = score_matrix[
                row_index
            ]

            all_results.append(
                self._format_results(
                    scores,
                    indices,
                )
            )

        return all_results

    # =========================================================
    # Result formatting
    # =========================================================

    def _format_results(
        self,
        scores,
        indices,
    ):
        results = []

        for rank, index in enumerate(
            indices,
            start=1,
        ):
            row = self.cwe_df.iloc[
                int(index)
            ]

            results.append(
                {
                    "rank": rank,
                    "cwe_id": row[
                        "cwe_id"
                    ],
                    "name": row[
                        "name"
                    ],
                    "score": float(
                        scores[int(index)]
                    ),
                }
            )

        return results

    def get_candidate_count(self):
        return len(
            self.cwe_df
        )


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
                "An attacker can use ../ "
                "sequences to access files "
                "outside the intended directory."
            ),
        ),
        (
            "SQL Injection",
            (
                "Unsanitized user input is "
                "directly inserted into "
                "a SQL query."
            ),
        ),
        (
            "Cross-site Scripting",
            (
                "User controlled input is "
                "rendered in a web page "
                "without proper escaping."
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
                f"score="
                f"{result['score']:.4f}"
            )


if __name__ == "__main__":
    main()