#!/usr/bin/env python3

from pathlib import Path
import sys
import pandas as pd

DATA_ROOT = Path("/home/data")
PROCESSED = DATA_ROOT / "processed"
RESULTS = DATA_ROOT / "results"

FILES = {
    "cve_clean": PROCESSED / "cve_clean.csv",
    "cwe_clean": PROCESSED / "cwe_clean.csv",
    "pairs": PROCESSED / "cve_cwe_pairs.csv",
    "top25": PROCESSED / "cve_cwe_top25.csv",
    "top50": PROCESSED / "cve_cwe_top50.csv",
    "distribution": RESULTS / "cwe_distribution.csv",
}

PAIR_COLS = [
    "cve_id",
    "cve_description",
    "cwe_id",
    "cwe_name",
    "cwe_search_text",
    "year",
]

DIST_COLS = ["cwe_id", "cwe_name", "cve_count"]

INVALID_CWE = {"NVD-CWE-NOINFO", "NVD-CWE-OTHER"}


def ok(msg):
    print(f"[PASS] {msg}")


def fail(msg):
    print(f"[FAIL] {msg}")


def require_columns(df, required, name):
    missing = [c for c in required if c not in df.columns]
    if missing:
        fail(f"{name}: missing columns {missing}")
        return False
    ok(f"{name}: required columns found")
    return True


def no_missing(df, columns, name):
    passed = True
    for col in columns:
        s = df[col]
        count = int(s.isna().sum())
        if s.dtype == object:
            count += int((s.fillna("").astype(str).str.strip() == "").sum())
        if count:
            fail(f"{name}: {col} has {count:,} missing/empty values")
            passed = False
        else:
            ok(f"{name}: {col} has no missing values")
    return passed


def validate_main_dataset(cve, cwe, pairs):
    passed = True

    expected = (
        cve.merge(
            cwe[["cwe_id", "name", "search_text"]],
            on="cwe_id",
            how="inner",
        )
        .rename(
            columns={
                "description": "cve_description",
                "name": "cwe_name",
                "search_text": "cwe_search_text",
            }
        )[PAIR_COLS]
    )

    if len(expected) == len(pairs):
        ok("cve_cwe_pairs.csv row count matches the expected CVE-CWE inner join")
    else:
        fail(
            f"cve_cwe_pairs.csv row count mismatch: "
            f"expected {len(expected):,}, got {len(pairs):,}"
        )
        passed = False

    expected_ids = set(expected["cve_id"])
    actual_ids = set(pairs["cve_id"])

    if expected_ids == actual_ids:
        ok("cve_cwe_pairs.csv contains exactly the expected CVE IDs")
    else:
        fail("cve_cwe_pairs.csv CVE IDs do not match the expected join")
        print("  Missing examples:", sorted(expected_ids - actual_ids)[:10])
        print("  Extra examples:", sorted(actual_ids - expected_ids)[:10])
        passed = False

    return passed


def validate_common(df, cwe_ids, name):
    passed = True

    passed &= require_columns(df, PAIR_COLS, name)
    if not passed:
        return False

    passed &= no_missing(df, PAIR_COLS, name)

    dup = int(df["cve_id"].duplicated().sum())
    if dup == 0:
        ok(f"{name}: no duplicate cve_id")
    else:
        fail(f"{name}: {dup:,} duplicate cve_id values")
        passed = False

    bad_values = set(df["cwe_id"].astype(str).str.upper()) & INVALID_CWE
    if not bad_values:
        ok(f"{name}: no invalid NVD CWE placeholders")
    else:
        fail(f"{name}: invalid CWE values found: {sorted(bad_values)}")
        passed = False

    missing_cwe = sorted(set(df["cwe_id"].astype(str)) - cwe_ids)
    if not missing_cwe:
        ok(f"{name}: every cwe_id exists in cwe_clean.csv")
    else:
        fail(f"{name}: {len(missing_cwe)} CWE IDs missing from cwe_clean.csv")
        print("  Examples:", missing_cwe[:10])
        passed = False

    return passed


def validate_top_n(pairs, subset, n, name):
    passed = True

    actual_count = subset["cwe_id"].nunique()
    if actual_count == n:
        ok(f"{name}: contains exactly {n} CWE classes")
    else:
        fail(f"{name}: expected {n} CWE classes, found {actual_count}")
        passed = False

    expected_cwes = set(pairs["cwe_id"].value_counts().head(n).index)
    actual_cwes = set(subset["cwe_id"].unique())

    if expected_cwes == actual_cwes:
        ok(f"{name}: contains the correct Top {n} CWE classes")
    else:
        fail(f"{name}: CWE class selection is not the correct Top {n}")
        print("  Missing:", sorted(expected_cwes - actual_cwes))
        print("  Extra:", sorted(actual_cwes - expected_cwes))
        passed = False

    expected_ids = set(pairs[pairs["cwe_id"].isin(expected_cwes)]["cve_id"])
    actual_ids = set(subset["cve_id"])

    if expected_ids == actual_ids:
        ok(f"{name}: contains all and only CVEs belonging to the Top {n} classes")
    else:
        fail(f"{name}: row membership does not match expected Top {n} dataset")
        print(f"  Expected CVEs: {len(expected_ids):,}")
        print(f"  Actual CVEs:   {len(actual_ids):,}")
        passed = False

    return passed


def validate_distribution(pairs, dist):
    if not require_columns(dist, DIST_COLS, "cwe_distribution.csv"):
        return False

    passed = no_missing(dist, DIST_COLS, "cwe_distribution.csv")

    try:
        actual = dist.copy()
        actual["cve_count"] = pd.to_numeric(actual["cve_count"])
    except Exception:
        fail("cwe_distribution.csv: cve_count must be numeric")
        return False

    expected = (
        pairs.groupby(["cwe_id", "cwe_name"])
        .size()
        .reset_index(name="cve_count")
        .sort_values(["cve_count", "cwe_id"], ascending=[False, True])
        .reset_index(drop=True)
    )

    actual = (
        actual[DIST_COLS]
        .sort_values(["cve_count", "cwe_id"], ascending=[False, True])
        .reset_index(drop=True)
    )

    if expected.equals(actual):
        ok("cwe_distribution.csv exactly matches cve_cwe_pairs.csv")
    else:
        fail("cwe_distribution.csv does not match cve_cwe_pairs.csv")
        passed = False

    counts = dist["cve_count"].tolist()
    if counts == sorted(counts, reverse=True):
        ok("cwe_distribution.csv is sorted by cve_count descending")
    else:
        fail("cwe_distribution.csv is not sorted by cve_count descending")
        passed = False

    return passed


def main():
    print("=" * 70)
    print("STEP 2 VALIDATION")
    print("=" * 70)

    missing_files = [str(p) for p in FILES.values() if not p.exists()]
    if missing_files:
        for path in missing_files:
            fail(f"Missing required file: {path}")
        sys.exit(1)

    for path in FILES.values():
        ok(f"File exists: {path}")

    cve = pd.read_csv(FILES["cve_clean"])
    cwe = pd.read_csv(FILES["cwe_clean"])
    pairs = pd.read_csv(FILES["pairs"])
    top25 = pd.read_csv(FILES["top25"])
    top50 = pd.read_csv(FILES["top50"])
    dist = pd.read_csv(FILES["distribution"])

    print()
    print("Dataset sizes")
    print(f"  cve_clean.csv:        {len(cve):,}")
    print(f"  cwe_clean.csv:        {len(cwe):,}")
    print(f"  cve_cwe_pairs.csv:    {len(pairs):,}")
    print(f"  cve_cwe_top25.csv:    {len(top25):,}")
    print(f"  cve_cwe_top50.csv:    {len(top50):,}")
    print(f"  cwe_distribution.csv: {len(dist):,}")
    print()

    checks = []

    checks.append(require_columns(pairs, PAIR_COLS, "cve_cwe_pairs.csv"))
    if not checks[-1]:
        sys.exit(1)

    cwe_ids = set(cwe["cwe_id"].astype(str))

    checks.append(validate_common(pairs, cwe_ids, "cve_cwe_pairs.csv"))
    checks.append(validate_common(top25, cwe_ids, "cve_cwe_top25.csv"))
    checks.append(validate_common(top50, cwe_ids, "cve_cwe_top50.csv"))

    checks.append(validate_main_dataset(cve, cwe, pairs))
    checks.append(validate_top_n(pairs, top25, 25, "cve_cwe_top25.csv"))
    checks.append(validate_top_n(pairs, top50, 50, "cve_cwe_top50.csv"))
    checks.append(validate_distribution(pairs, dist))

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(f"Final CVE-CWE pairs: {len(pairs):,}")
    print(f"Unique CWE classes:  {pairs['cwe_id'].nunique():,}")
    print(f"Top 25 rows:         {len(top25):,}")
    print(f"Top 50 rows:         {len(top50):,}")

    print()
    print("Top 10 CWE classes:")
    print(
        pairs.groupby(["cwe_id", "cwe_name"])
        .size()
        .reset_index(name="cve_count")
        .sort_values("cve_count", ascending=False)
        .head(10)
        .to_string(index=False)
    )

    print()

    if all(checks):
        print("STEP 2 VALIDATION PASSED")
        print("Dataset is ready for the retrieval-model stage.")
        sys.exit(0)

    print("STEP 2 VALIDATION FAILED")
    print("Fix the failed checks before starting retrieval experiments.")
    sys.exit(1)


if __name__ == "__main__":
    main()