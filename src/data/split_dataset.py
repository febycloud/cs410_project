from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


DATA_ROOT = Path("/home/data")
INPUT_FILE = DATA_ROOT / "processed" / "cve_cwe_top50.csv"

TRAIN_FILE = DATA_ROOT / "processed" / "train.csv"
TEST_FILE = DATA_ROOT / "processed" / "test.csv"


def main():
    df = pd.read_csv(INPUT_FILE)

    required_columns = [
        "cve_id",
        "cve_description",
        "cwe_id",
    ]

    missing = [
        col for col in required_columns
        if col not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required columns: {missing}"
        )

    df = df[required_columns].copy()

    # Basic cleanup
    df = df.dropna(
        subset=[
            "cve_id",
            "cve_description",
            "cwe_id",
        ]
    )

    df = df.drop_duplicates(
        subset=["cve_id"]
    )

    print("Total rows:", len(df))
    print("Unique CWE:", df["cwe_id"].nunique())

    train_df, test_df = train_test_split(
        df,
        test_size=0.20,
        random_state=42,
        stratify=df["cwe_id"],
    )

    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    train_df.to_csv(
        TRAIN_FILE,
        index=False,
        encoding="utf-8",
    )

    test_df.to_csv(
        TEST_FILE,
        index=False,
        encoding="utf-8",
    )

    print()
    print("Train rows:", len(train_df))
    print("Test rows:", len(test_df))

    print(
        "Train unique CWE:",
        train_df["cwe_id"].nunique(),
    )

    print(
        "Test unique CWE:",
        test_df["cwe_id"].nunique(),
    )

    print()
    print("Saved:")
    print(TRAIN_FILE)
    print(TEST_FILE)


if __name__ == "__main__":
    main()