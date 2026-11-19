from pathlib import Path
from typing import Literal
import os
import re

import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.models.tfidf_retriever import TfidfRetriever
from src.models.bm25_retriever import BM25Retriever
from src.models.minilm_retriever import MiniLMRetriever


# ============================================================
# Configuration
# ============================================================

DATA_ROOT = Path(
    os.getenv("DATA_ROOT", "/home/data")
)

CVE_FILE = (
    DATA_ROOT
    / "processed"
    / "cve_clean.csv"
)

CVE_PATTERN = re.compile(
    r"^CVE-\d{4}-\d+$",
    re.IGNORECASE,
)


# ============================================================
# FastAPI app
# ============================================================

app = FastAPI(
    title="CVE to CWE Retrieval API",
    description=(
        "Retrieve relevant CWE categories from either "
        "a CVE ID or a natural-language vulnerability description."
    ),
    version="1.0.0",
)


# ============================================================
# Lazy-loaded resources
# ============================================================

_retrievers = {}

_cve_df = None
_cve_lookup = None


# ============================================================
# Request / Response models
# ============================================================

class SearchRequest(BaseModel):
    query: str = Field(
        ...,
        min_length=1,
        description=(
            "CVE ID or natural-language vulnerability description"
        ),
        examples=[
            "CVE-2024-12345",
            (
                "Unsanitized user input is directly "
                "inserted into a SQL query."
            ),
        ],
    )

    model: Literal[
        "tfidf",
        "bm25",
        "minilm",
    ] = Field(
        default="tfidf",
        description="Retrieval model",
    )

    top_k: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Number of CWE results to return",
    )


class CWERecord(BaseModel):
    rank: int
    cwe_id: str
    name: str
    score: float


class SearchResponse(BaseModel):
    input_type: str

    original_query: str

    resolved_query: str

    cve_id: str | None = None

    model: str

    top_k: int

    results: list[CWERecord]


# ============================================================
# CVE data
# ============================================================

def load_cve_lookup():
    """
    Load CVE data only when CVE lookup is first needed.
    """

    global _cve_df
    global _cve_lookup

    if _cve_lookup is not None:
        return _cve_lookup

    if not CVE_FILE.exists():
        raise RuntimeError(
            f"CVE dataset not found: {CVE_FILE}"
        )

    df = pd.read_csv(
        CVE_FILE,
        usecols=[
            "cve_id",
            "description",
        ],
    )

    df = df.dropna(
        subset=[
            "cve_id",
            "description",
        ]
    ).copy()

    df["cve_id"] = (
        df["cve_id"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    df["description"] = (
        df["description"]
        .astype(str)
        .str.strip()
    )

    df = (
        df[
            df["description"].str.len() > 0
        ]
        .drop_duplicates(
            subset=["cve_id"]
        )
        .reset_index(drop=True)
    )

    _cve_df = df

    _cve_lookup = dict(
        zip(
            df["cve_id"],
            df["description"],
        )
    )

    print(
        f"Loaded {len(_cve_lookup):,} "
        "CVE descriptions for API lookup"
    )

    return _cve_lookup


def resolve_query(
    query: str,
):
    """
    Determine whether input is a CVE ID
    or natural-language description.

    Returns:
        input_type
        resolved_query
        cve_id
    """

    query = query.strip()

    if not query:
        raise ValueError(
            "Query cannot be empty"
        )

    if CVE_PATTERN.fullmatch(query):
        cve_id = query.upper()

        lookup = load_cve_lookup()

        description = lookup.get(
            cve_id
        )

        if description is None:
            raise LookupError(
                f"CVE not found in local dataset: {cve_id}"
            )

        return (
            "cve_id",
            description,
            cve_id,
        )

    return (
        "natural_language",
        query,
        None,
    )


# ============================================================
# Retriever loading
# ============================================================

def get_retriever(
    model_name: str,
):
    """
    Lazy-load each retriever only once.
    """

    if model_name in _retrievers:
        return _retrievers[
            model_name
        ]

    if model_name == "tfidf":
        retriever = (
            TfidfRetriever()
        )

    elif model_name == "bm25":
        retriever = (
            BM25Retriever()
        )

    elif model_name == "minilm":
        retriever = (
            MiniLMRetriever()
        )

    else:
        raise ValueError(
            f"Unsupported model: {model_name}"
        )

    _retrievers[
        model_name
    ] = retriever

    return retriever


# ============================================================
# Routes
# ============================================================

@app.get("/")
def root():
    return {
        "name": "CVE to CWE Retrieval API",
        "version": "1.0.0",
        "models": [
            "tfidf",
            "bm25",
            "minilm",
        ],
        "input_types": [
            "CVE ID",
            "Natural-language vulnerability description",
        ],
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


@app.get("/models")
def models():
    return {
        "models": [
            {
                "id": "tfidf",
                "name": "TF-IDF",
            },
            {
                "id": "bm25",
                "name": "BM25",
            },
            {
                "id": "minilm",
                "name": "MiniLM",
            },
        ]
    }


@app.post(
    "/search",
    response_model=SearchResponse,
)
def search(
    request: SearchRequest,
):
    original_query = (
        request.query.strip()
    )

    # --------------------------------------------------------
    # Resolve CVE ID or natural language
    # --------------------------------------------------------

    try:
        (
            input_type,
            resolved_query,
            cve_id,
        ) = resolve_query(
            original_query
        )

    except LookupError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        )

    # --------------------------------------------------------
    # Load model
    # --------------------------------------------------------

    try:
        retriever = get_retriever(
            request.model
        )

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        )

    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    # --------------------------------------------------------
    # Retrieval
    # --------------------------------------------------------

    try:
        results = retriever.search(
            query=resolved_query,
            top_k=request.top_k,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Retrieval failed: "
                f"{type(exc).__name__}: {exc}"
            ),
        )

    return {
        "input_type": input_type,
        "original_query": original_query,
        "resolved_query": resolved_query,
        "cve_id": cve_id,
        "model": request.model,
        "top_k": request.top_k,
        "results": results,
    }