import pandas as pd

from data_util import (
    CWE_RAW_FILE,
    CWE_CLEAN_FILE,
    ensure_directories,
    normalize_cwe_id,
    clean_text,
    save_csv,
)


def main():
    ensure_directories()

    print(f"Reading:")
    print(CWE_RAW_FILE)

    df = pd.read_csv(
    CWE_RAW_FILE,
    dtype=str,
    keep_default_na=False,
    index_col=False,
)

    print(f"Raw CWE rows: {len(df):,}")
    print(df.columns.tolist())
    print(df["CWE-ID"].head(10).tolist())
    print(df[["CWE-ID", "Name"]].head(10))

    required_columns = [
        "CWE-ID",
        "Name",
        "Description",
        "Extended Description",
    ]

    missing = [
        col
        for col in required_columns
        if col not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing expected columns: {missing}"
        )

    clean_df = pd.DataFrame()

    clean_df["cwe_id"] = (
        df["CWE-ID"]
        .apply(normalize_cwe_id)
    )

    clean_df["name"] = (
        df["Name"]
        .apply(clean_text)
    )

    clean_df["description"] = (
        df["Description"]
        .apply(clean_text)
    )

    clean_df["extended_description"] = (
        df["Extended Description"]
        .apply(clean_text)
    )

    # Search text will later be used by:
    # TF-IDF, BM25, and MiniLM.
    clean_df["search_text"] = (
        clean_df["name"]
        + ". "
        + clean_df["description"]
        + " "
        + clean_df["extended_description"]
    ).apply(clean_text)

    # Remove invalid IDs.
    clean_df = clean_df.dropna(
        subset=["cwe_id"]
    )

    # Remove entries without useful text.
    clean_df = clean_df[
        clean_df["search_text"].str.len() > 0
    ]

    # Remove duplicate CWE IDs.
    clean_df = clean_df.drop_duplicates(
        subset=["cwe_id"]
    )

    clean_df = clean_df.sort_values(
        "cwe_id"
    ).reset_index(drop=True)

    print(f"Clean CWE rows: {len(clean_df):,}")

    print()
    print(clean_df.head())

    print()

    save_csv(
        clean_df,
        CWE_CLEAN_FILE,
    )


if __name__ == "__main__":
    main()