"""Shared, conservative query preprocessing for every retriever."""

import re


CWE_MENTION = re.compile(r"\(?\bCWE[-\s]?\d+\b\)?", re.IGNORECASE)


def remove_cwe_ids(text: str) -> str:
    """Remove explicit CWE labels and normalize the whitespace they leave."""
    if not isinstance(text, str):
        return ""
    return " ".join(CWE_MENTION.sub(" ", text).split())
