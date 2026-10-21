import json
from pathlib import Path

import pandas as pd

from data_util import (
    NVD_DIR,
    CVE_CLEAN_FILE,
    ensure_directories,
    clean_text,
    normalize_cwe_id,
    save_csv,
)


INVALID_CWE_VALUES = {
    "NVD-CWE-NOINFO",
    "NVD-CWE-OTHER",
}


def get_english_description(cve):
    """
    Extract English CVE description from NVD JSON.
    """
    descriptions = cve.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return clean_text(item.get("value", ""))

    return ""


def get_cwe_ids(cve):
    """
    Extract valid CWE IDs from an NVD CVE record.
    """
    found = set()

    weaknesses = cve.get("weaknesses", [])

    for weakness in weaknesses:
        descriptions = weakness.get("description", [])

        for item in descriptions:
            value = str(item.get("value", "")).strip()

            if not value:
                continue

            if value.upper() in INVALID_CWE_VALUES:
                continue

            normalized = normalize_cwe_id(value)

            if normalized:
                found.add(normalized)

    return sorted(found)


def extract_year(cve_id):
    """
    Example:
        CVE-2024-12345 -> 2024
    """
    try:
        return int(cve_id.split("-")[1])
    except (IndexError, ValueError):
        return None


def process_nvd_file(path):
    """
    Read one NVD 2.0 JSON file and return cleaned records.

    First version rule:
    keep only CVEs with exactly one valid CWE mapping.
    """
    print(f"Processing: {path.name}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    records = []

    vulnerabilities = data.get("vulnerabilities", [])

    for item in vulnerabilities:
        cve = item.get("cve", {})

        cve_id = cve.get("id", "").strip()

        if not cve_id:
            continue

        description = get_english_description(cve)

        if not description:
            continue

        cwe_ids = get_cwe_ids(cve)

        # For the first version, keep only single-CWE records.
        if len(cwe_ids) != 1:
            continue

        records.append(
            {
                "cve_id": cve_id,
                "description": description,
                "cwe_id": cwe_ids[0],
                "year": extract_year(cve_id),
            }
        )

    print(f"  Kept {len(records):,} records")

    return records


def main():
    ensure_directories()

    json_files = sorted(NVD_DIR.glob("*.json"))

    if not json_files:
        raise FileNotFoundError(
            f"No JSON files found in {NVD_DIR}"
        )

    all_records = []

    for path in json_files:
        all_records.extend(process_nvd_file(path))

    df = pd.DataFrame(all_records)

    print()
    print("Before duplicate removal:", len(df))

    df = df.drop_duplicates(subset=["cve_id"])

    df = df.dropna(
        subset=[
            "cve_id",
            "description",
            "cwe_id",
        ]
    )

    df = df.sort_values(
        by=["year", "cve_id"]
    ).reset_index(drop=True)

    print("After cleaning:", len(df))
    print("Unique CWE:", df["cwe_id"].nunique())

    print()
    print("Top 10 CWE categories:")
    print(df["cwe_id"].value_counts().head(10))

    print()

    save_csv(
        df,
        CVE_CLEAN_FILE,
    )


if __name__ == "__main__":
    main()