from functools import lru_cache
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="CVE to CWE Retrieval API",
    description=(
        "Retrieve the most relevant CWE categories "
        "from a vulnerability description."
    ),
    version="1.0.0",
)


@lru_cache(maxsize=3)
def get_retriever(model: str):
    """Initialize each requested model once, without loading data at import time."""
    if model == "tfidf":
        from src.models.tfidf_retriever import TfidfRetriever
        return TfidfRetriever()
    if model == "bm25":
        from src.models.bm25_retriever import BM25Retriever
        return BM25Retriever()
    if model == "minilm":
        from src.models.minilm_retriever import MiniLMRetriever
        return MiniLMRetriever()
    raise ValueError(f"Unsupported model: {model}")


class SearchRequest(BaseModel):
    query: str = Field(
        ...,
        min_length=1,
        description="Vulnerability description",
    )

    model: Literal["tfidf", "bm25", "minilm"] = "tfidf"

    top_k: int = Field(
        default=5,
        ge=1,
        le=10,
    )


@app.get("/")
def root():
    return {
        "message": "CVE to CWE Retrieval API",
        "models": [
            "tfidf",
            "bm25",
            "minilm",
        ],
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


@app.post("/search")
def search(request: SearchRequest):
    try:
        retriever = get_retriever(request.model)
    except (FileNotFoundError, ImportError, OSError, RuntimeError, ValueError) as e:
        raise HTTPException(
            status_code=503,
            detail=f"Model is unavailable: {e}",
        )

    try:
        results = retriever.search(
            query=request.query,
            top_k=request.top_k,
        )

        return {
            "query": request.query,
            "model": request.model,
            "top_k": request.top_k,
            "results": results,
        }

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e),
        )
