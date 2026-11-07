"""
Step 2: build the final CVE-CWE dataset.

Inputs (read only, never modified):
    /home/data/processed/cve_clean.csv   cve_id, description, cwe_id, year
    /home/data/processed/cwe_clean.csv   cwe_id, name, description, extended_description, search_text

Outputs:
    /home/data/processed/cve_cwe_pairs.csv     full master dataset (all matched CVEs)
    /home/data/processed/cve_cwe_top25.csv     only the 25 most frequent CWEs
    /home/data/processed/cve_cwe_top50.csv     only the 50 most frequent CWEs
    /home/data/results/cwe_distribution.csv    number of CVEs per CWE, highest first
    /home/data/results/dataset_summary.txt     everything printed in the summary + validation

Tasks (numbering follows the Step 2 handoff document):
    2.1 Align CVE and CWE: drop CVEs whose cwe_id is not defined in cwe_clean.csv
    2.2 Build the full CVE-CWE pair dataset
    2.3 Count CVEs per CWE
    2.4 Print and save a dataset summary
    2.5 Build the Top 25 / Top 50 datasets
    2.6 Final validation: exit with code 1 if any check fails

Run from the project root:
    python -m src.data.build_dataset
or from inside src/data:
    python build_dataset.py
"""
import sys

import pandas as pd

# The import works both ways the script can be started:
#   python -m src.data.build_dataset  -> package import (.data_util)
#   python build_dataset.py           -> plain import (data_util)
try:
    from .data_util import (
        DATA_ROOT, PROCESSED_DIR, CVE_CLEAN_FILE, CWE_CLEAN_FILE,
        normalize_cwe_id, save_csv,
    )
except ImportError:
    from data_util import (
        DATA_ROOT, PROCESSED_DIR, CVE_CLEAN_FILE, CWE_CLEAN_FILE,
        normalize_cwe_id, save_csv,
    )


# ---------------------------------------------------------------------------
# Output locations
# ---------------------------------------------------------------------------

RESULTS_DIR = DATA_ROOT / "results"

PAIRS_FILE = PROCESSED_DIR / "cve_cwe_pairs.csv"
DISTRIBUTION_FILE = RESULTS_DIR / "cwe_distribution.csv"
SUMMARY_FILE = RESULTS_DIR / "dataset_summary.txt"

# One output file per Top-K version. To add e.g. a Top 10 version,
# add an entry here; the rest of the script picks it up automatically.
TOP_FILES = {
    25: PROCESSED_DIR / "cve_cwe_top25.csv",
    50: PROCESSED_DIR / "cve_cwe_top50.csv",
}


# ---------------------------------------------------------------------------
# Column definitions and constants
# ---------------------------------------------------------------------------

# Column order of every output dataset (pairs, top25, top50).
PAIR_COLUMNS = [
    "cve_id",
    "cve_description",
    "cwe_id",
    "cwe_name",
    "cwe_search_text",
    "year",
]

# Columns the script needs from each input file. Extra columns are ignored,
# so the script also works if cve_clean.csv gains more columns later.
REQUIRED_CVE_COLUMNS = ["cve_id", "description", "cwe_id", "year"]
REQUIRED_CWE_COLUMNS = ["cwe_id", "name", "search_text"]

# NVD placeholder values that are not real CWE IDs.
INVALID_CWE_VALUES = {"NVD-CWE-NOINFO", "NVD-CWE-OTHER"}

# Columns that must never be empty in the outputs (Task 2.6).
NON_EMPTY_COLUMNS = ["cve_id", "cve_description", "cwe_id", "cwe_name", "cwe_search_text"]

# Minimum-frequency cut-offs shown in the summary. They help decide between
# Top 25, Top 50, or "keep every CWE with at least N CVEs".
FREQUENCY_THRESHOLDS = [50, 100, 200, 500, 1000]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def read_csv(path):
    """
    Read every column as a string.
    keep_default_na=False keeps empty cells as "" instead of NaN, so a check
    like `df[col] == ""` finds every empty value.
    """
    return pd.read_csv(path, dtype=str, keep_default_na=False)


def clean_id(value):
    """
    Normalize a CWE ID ("cwe-22", " 22 ", "CWE-022" -> "CWE-22").
    Values that cannot be normalized (e.g. NVD-CWE-noinfo) are kept as they are,
    upper-cased, so they can still be counted and reported correctly.
    """
    value = str(value).strip()
    normalized = normalize_cwe_id(value)
    return normalized if normalized else value.upper()


def cwe_number(cwe_id):
    """CWE-79 -> 79. Used to break ties in numeric order (CWE-22 before CWE-100)."""
    try:
        return int(str(cwe_id).split("-", 1)[1])
    except (IndexError, ValueError):
        return 10**9


def cve_sort_key(cve_ids):
    """
    Numeric sort key for CVE IDs.
    Plain string sorting puts CVE-2023-10000 before CVE-2023-9999;
    sorting by (year, sequence number) gives the natural order.
    """
    parts = cve_ids.str.extract(r"CVE-(\d+)-(\d+)", expand=True)
    year = pd.to_numeric(parts[0], errors="coerce").fillna(0)
    seq = pd.to_numeric(parts[1], errors="coerce").fillna(0)
    return year * 10**8 + seq


def check_columns(df, required, name):
    """Stop early with a clear message if an input file is missing a column."""
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"{name} is missing columns: {missing}")


class Summary:
    """
    Collects every summary line so it is printed to the terminal AND saved
    to dataset_summary.txt ("统计结果已经打印并记录").
    """

    def __init__(self):
        self.lines = []

    def add(self, line=""):
        print(line)
        self.lines.append(line)

    def save(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.lines) + "\n")
        print(f"Summary saved to: {path}")


# ---------------------------------------------------------------------------
# Task 2.1 - Load and align CVE with CWE
# ---------------------------------------------------------------------------

def load_inputs():
    """Read both cleaned files and normalize the key columns (in memory only)."""
    print(f"Reading: {CVE_CLEAN_FILE}")
    cve = read_csv(CVE_CLEAN_FILE)
    print(f"Reading: {CWE_CLEAN_FILE}")
    cwe = read_csv(CWE_CLEAN_FILE)

    check_columns(cve, REQUIRED_CVE_COLUMNS, "cve_clean.csv")
    check_columns(cwe, REQUIRED_CWE_COLUMNS, "cwe_clean.csv")

    # Strip stray whitespace so " CVE-2024-1 " and "CVE-2024-1" are the same record.
    for col in ["cve_id", "description", "year"]:
        cve[col] = cve[col].str.strip()

    # Normalize CWE IDs on BOTH sides so a formatting difference
    # (e.g. "cwe-22" vs "CWE-22") never causes a false mismatch.
    cve["cwe_id"] = cve["cwe_id"].apply(clean_id)
    cwe["cwe_id"] = cwe["cwe_id"].apply(clean_id)

    # An empty cwe_id in cwe_clean.csv must not count as a valid definition,
    # otherwise CVEs with an empty cwe_id would "match" it.
    cwe = cwe[cwe["cwe_id"] != ""]

    # Keep one definition per CWE ID (cwe_clean.csv should already be unique).
    cwe = cwe.drop_duplicates(subset=["cwe_id"], keep="first")

    return cve, cwe


def align(cve, cwe):
    """
    Remove duplicate CVE IDs, then keep only CVEs whose cwe_id is defined in
    cwe_clean.csv. Every removed record is counted in exactly one category,
    so the numbers in the summary always add up.
    """
    valid_ids = set(cwe["cwe_id"])
    info = {"before": len(cve)}

    # 1) Duplicate CVE IDs: keep the first occurrence.
    duplicated = cve["cve_id"].duplicated(keep="first")
    info["removed_duplicate_cve_id"] = int(duplicated.sum())
    cve = cve[~duplicated]

    # Unique CWE count before matching (real IDs only, placeholders excluded).
    real_ids = (cve["cwe_id"] != "") & ~cve["cwe_id"].isin(INVALID_CWE_VALUES)
    info["unique_before"] = cve.loc[real_ids, "cwe_id"].nunique()

    # 2) Classify every record by why it would be removed.
    is_empty = cve["cwe_id"] == ""
    is_placeholder = cve["cwe_id"].isin(INVALID_CWE_VALUES)
    is_matched = cve["cwe_id"].isin(valid_ids)
    is_unknown = ~is_empty & ~is_placeholder & ~is_matched

    info["removed_empty_cwe"] = int(is_empty.sum())
    info["removed_placeholder"] = int(is_placeholder.sum())
    info["removed_not_in_cwe_table"] = int(is_unknown.sum())

    # The most common unknown IDs show whether a mapping is worth adding later.
    info["top_unmatched"] = cve.loc[is_unknown, "cwe_id"].value_counts().head(20)

    matched = cve[is_matched].copy()
    info["after"] = len(matched)
    info["removed"] = info["before"] - info["after"]
    info["unique_after"] = matched["cwe_id"].nunique()

    return matched, info


# ---------------------------------------------------------------------------
# Task 2.2 - Full pair dataset
# ---------------------------------------------------------------------------

def build_pairs(cve, cwe):
    """Attach the CWE name and search_text to every CVE (one row per CVE)."""
    cwe_cols = cwe[["cwe_id", "name", "search_text"]].rename(
        columns={"name": "cwe_name", "search_text": "cwe_search_text"}
    )

    # many_to_one: many CVEs can share one CWE, but each CWE appears once.
    # pandas raises an error if cwe_clean.csv still had duplicate IDs.
    pairs = cve.rename(columns={"description": "cve_description"}).merge(
        cwe_cols, on="cwe_id", how="left", validate="many_to_one"
    )

    # Stable, natural order: by year, then by CVE number.
    pairs = pairs.assign(_key=cve_sort_key(pairs["cve_id"]))
    pairs = pairs.sort_values(["_key"], kind="stable").drop(columns="_key")

    return pairs[PAIR_COLUMNS].reset_index(drop=True)


# ---------------------------------------------------------------------------
# Task 2.3 - CWE distribution
# ---------------------------------------------------------------------------

def build_distribution(pairs):
    """Count CVEs per CWE, highest count first."""
    dist = (
        pairs.groupby(["cwe_id", "cwe_name"])
        .size()
        .reset_index(name="cve_count")
    )

    # Ties are broken by CWE number so the ranking (and therefore the
    # Top 25 / Top 50 selection) is identical on every run.
    dist["_num"] = dist["cwe_id"].apply(cwe_number)
    dist = (
        dist.sort_values(["cve_count", "_num"], ascending=[False, True])
        .drop(columns="_num")
        .reset_index(drop=True)
    )
    return dist


# ---------------------------------------------------------------------------
# Task 2.5 - Top-K datasets
# ---------------------------------------------------------------------------

def boundary_tie(dist, k):
    """
    Return the tied count if the k-th and (k+1)-th CWE have the same number
    of CVEs, else None. In that case the cut-off was decided by CWE number,
    not by frequency, and the summary should say so.
    """
    if len(dist) <= k:
        return None
    kth = dist.iloc[k - 1]["cve_count"]
    nxt = dist.iloc[k]["cve_count"]
    return int(kth) if kth == nxt else None


def build_top_k(pairs, dist, k):
    """Keep only the CVEs that belong to the k most frequent CWEs."""
    top_ids = set(dist.head(k)["cwe_id"])
    return pairs[pairs["cwe_id"].isin(top_ids)].reset_index(drop=True)


# ---------------------------------------------------------------------------
# Task 2.4 - Summary
# ---------------------------------------------------------------------------

def add_top_table(summary, dist, k, total):
    """Print the Top-K table: rank, ID, count, cumulative share of all pairs, name."""
    top = dist.head(k).copy()
    top["cumulative_share"] = top["cve_count"].cumsum() / total

    summary.add(f"Top {k} CWE")
    summary.add(f"{'Rank':>4}  {'CWE ID':<9} {'CVE Count':>9}  {'Cum. %':>6}  CWE Name")
    for rank, row in enumerate(top.itertuples(index=False), start=1):
        # Long official names are shortened for the terminal only;
        # the CSV files keep the full name.
        name = row.cwe_name if len(row.cwe_name) <= 70 else row.cwe_name[:67] + "..."
        summary.add(
            f"{rank:>4}  {row.cwe_id:<9} {row.cve_count:>9,}  "
            f"{row.cumulative_share:>6.1%}  {name}"
        )
    summary.add()


def add_summary(summary, info, pairs, dist):
    total = len(pairs)

    summary.add()
    summary.add("=" * 70)
    summary.add("Dataset Summary")
    summary.add("=" * 70)
    summary.add(f"CVE records before CWE matching: {info['before']:,}")
    summary.add(f"CVE records after CWE matching:  {info['after']:,}")
    summary.add(f"Removed CVEs:                    {info['removed']:,}")
    summary.add(f"  - duplicate cve_id:            {info['removed_duplicate_cve_id']:,}")
    summary.add(f"  - empty cwe_id:                {info['removed_empty_cwe']:,}")
    summary.add(f"  - NVD-CWE-noinfo / Other:      {info['removed_placeholder']:,}")
    summary.add(f"  - cwe_id not in cwe_clean.csv: {info['removed_not_in_cwe_table']:,}")
    summary.add(f"Unique CWE before matching:      {info['unique_before']:,}")
    summary.add(f"Unique CWE after matching:       {info['unique_after']:,}")
    summary.add()

    if len(info["top_unmatched"]):
        summary.add("Most common removed CWE IDs (not in cwe_clean.csv):")
        for cwe_id, count in info["top_unmatched"].items():
            summary.add(f"  {cwe_id}: {count:,}")
        summary.add()

    for k in TOP_FILES:
        add_top_table(summary, dist, k, total)

    # How much of the data each Top-K version keeps, and how small its
    # rarest class is (very small classes make per-class metrics unstable).
    summary.add("Coverage")
    for k in TOP_FILES:
        top = dist.head(k)
        covered = int(top["cve_count"].sum())
        smallest = int(top["cve_count"].min()) if len(top) else 0
        summary.add(
            f"  Top {k}: {covered:,} CVEs ({covered / total:.1%} of all pairs), "
            f"smallest class has {smallest:,} CVEs"
        )
        tie = boundary_tie(dist, k)
        if tie is not None:
            summary.add(
                f"    Note: rank {k} and rank {k + 1} both have {tie:,} CVEs; "
                f"the cut-off was decided by CWE number."
            )
    summary.add()

    # Alternative to Top-K: keep every CWE with at least N CVEs.
    summary.add("CWE classes by minimum frequency")
    for t in FREQUENCY_THRESHOLDS:
        kept = dist[dist["cve_count"] >= t]
        n_cves = int(kept["cve_count"].sum())
        summary.add(
            f"  >= {t:>4} CVEs: {len(kept):>4} classes, {n_cves:,} CVEs ({n_cves / total:.1%})"
        )
    summary.add()


# ---------------------------------------------------------------------------
# Task 2.6 - Final validation
# ---------------------------------------------------------------------------

def validate(summary, name, df, valid_ids, expected_classes=None):
    """
    Run every check from Task 2.6 on one output dataset.
    Returns the list of failed checks (empty list = all passed).
    """
    failures = []

    def check(label, ok, detail=""):
        status = "PASS" if ok else "FAIL"
        summary.add(f"[{status}] {name}: {label}" + (f" ({detail})" if detail else ""))
        if not ok:
            failures.append(f"{name}: {label}")

    # No empty values in the key columns
    for col in NON_EMPTY_COLUMNS:
        empty = int((df[col].fillna("").astype(str).str.strip() == "").sum())
        check(f"{col} has no empty values", empty == 0, f"{empty:,} empty")

    # year must be a 4-digit year (needed later for a time-based train/test split)
    bad_year = int((~df["year"].astype(str).str.fullmatch(r"\d{4}")).sum())
    check("year is a 4-digit number", bad_year == 0, f"{bad_year:,} bad values")

    # One row per CVE
    dup = int(df["cve_id"].duplicated().sum())
    check("no duplicate cve_id", dup == 0, f"{dup:,} duplicates")

    # Every label has a CWE definition
    unknown = sorted(set(df["cwe_id"]) - valid_ids)
    check("all cwe_id exist in cwe_clean.csv", not unknown, f"unknown: {unknown[:10]}")

    # No NVD placeholder labels
    invalid = int(df["cwe_id"].str.upper().isin(INVALID_CWE_VALUES).sum())
    check("no NVD-CWE-noinfo / NVD-CWE-Other", invalid == 0, f"{invalid:,} rows")

    # Top-K files must contain exactly K classes
    if expected_classes is not None:
        n = df["cwe_id"].nunique()
        check(
            f"contains exactly {expected_classes} CWE classes",
            n == expected_classes,
            f"{n} classes",
        )

    return failures


# ---------------------------------------------------------------------------

def main():
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    cve, cwe = load_inputs()
    valid_ids = set(cwe["cwe_id"])

    # Task 2.1
    cve_matched, info = align(cve, cwe)

    # Task 2.2
    pairs = build_pairs(cve_matched, cwe)

    # Task 2.3
    dist = build_distribution(pairs)

    # Task 2.5
    top_datasets = {k: build_top_k(pairs, dist, k) for k in TOP_FILES}

    # Save all outputs. Files are written even if validation fails later,
    # so a failed run can still be inspected.
    print()
    save_csv(pairs, PAIRS_FILE)
    save_csv(dist, DISTRIBUTION_FILE)
    for k, df in top_datasets.items():
        save_csv(df, TOP_FILES[k])

    # Task 2.4
    summary = Summary()
    add_summary(summary, info, pairs, dist)

    # Task 2.6 (results also go into dataset_summary.txt)
    summary.add("=" * 70)
    summary.add("Final Validation")
    summary.add("=" * 70)
    failures = validate(summary, "cve_cwe_pairs", pairs, valid_ids)
    for k, df in top_datasets.items():
        failures += validate(summary, f"cve_cwe_top{k}", df, valid_ids, expected_classes=k)

    summary.add()
    if failures:
        summary.add(f"{len(failures)} check(s) FAILED:")
        for f in failures:
            summary.add(f"  - {f}")
    else:
        summary.add("All checks passed. Step 2 complete.")

    # Save the summary before exiting, so it is kept even when a check fails.
    summary.save(SUMMARY_FILE)

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
