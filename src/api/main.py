from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.models.tfidf_retriever import TfidfRetriever
from src.models.bm25_retriever import BM25Retriever


app = FastAPI(
    title="CVE to CWE Retrieval API",
    description=(
        "Retrieve the most relevant CWE categories "
        "from a vulnerability description."
    ),
    version="1.0.0",
)


# Initialize once when API starts
tfidf_retriever = TfidfRetriever()
bm25_retriever = BM25Retriever()


class SearchRequest(BaseModel):
    query: str = Field(
        ...,
        min_length=1,
        description="Vulnerability description",
    )

    model: Literal["tfidf", "bm25"] = "tfidf"

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
        if request.model == "tfidf":
            retriever = tfidf_retriever

        elif request.model == "bm25":
            retriever = bm25_retriever

        else:
            raise ValueError(
                f"Unsupported model: {request.model}"
            )

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