"""
Step 3: leakage-aware train / test split.

Replaces the plain random split. Same input, same output files, and the same
three core columns (cve_id, cve_description, cwe_id), so downstream code keeps
working. Extra columns are added for leakage-aware evaluation.

Input (read only, same file as v1):
    /home/data/processed/cve_cwe_top50.csv        (or top25 with --top 25)

Official outputs:
    Top 50:          /home/data/processed/train.csv
                     /home/data/processed/test.csv
                     /home/data/results/split_summary.txt
    With --top 25:   /home/data/processed/train_top25.csv
                     /home/data/processed/test_top25.csv
                     /home/data/results/split_summary_top25.txt

The retired v1 split, if retained for historical comparison, belongs under
/home/data/flagged_data/ and is never read or written by this script.

Leakage handled here (measured on the real Top 50 data):
    1. CWE IDs written in the description (e.g. "CWE-79"), 554 rows (0.7%)
       -> removed from cve_description.
    2. The official CWE name written in the description, 8,377 rows (10.8%)
       e.g. "Improper Neutralization of Input During Web Page Generation
       ('Cross-site Scripting') vulnerability in ...". TF-IDF gets these right
       97% of the time because the CWE document starts with the same words.
       -> NOT removed (removing it leaves almost no text). Marked with
          leak_flag so results can be reported on all rows AND on clean rows.
    3. Template descriptions: batches of CVEs with the same sentence except for
       product names / versions, 8,816 rows (11.3%). A random split puts the
       same template in train and test (10% of test rows), which raises
       nearest-neighbour Hit@1 from 0.60 to 0.88 on those rows.
       -> norm_key groups the templates; the split keeps every group on one side.

Output columns (train.csv and test.csv):
    cve_id            CVE ID
    cve_description   description with CWE IDs removed  <- use this as the query
    cwe_id            label
    year              CVE year
    leak_flag         0 = clean
                      1 = contains the official name of its own CWE
                      2 = contains the official name of another CWE
    norm_key          template key used for grouping (do not use as a feature)

How to evaluate with leak_flag:
    test = pd.read_csv("/home/data/processed/test.csv")
    report(test)                          # all test rows
    report(test[test["leak_flag"] == 0])  # clean rows only: the honest number

Usage (inside src/data):
    python split_dataset.py               # Top 50
    python split_dataset.py --top 25      # Top 25
"""
import argparse
import re
import sys

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

# Works both as "python split_dataset.py" and "python -m src.data.split_dataset".
try:
    from .data_util import DATA_ROOT, PROCESSED_DIR, save_csv
except ImportError:
    from data_util import DATA_ROOT, PROCESSED_DIR, save_csv


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

OUTPUT_DIR = PROCESSED_DIR
RESULTS_DIR = DATA_ROOT / "results"


def output_files(top):
    """Top 50: train.csv / test.csv; Top 25 gets a suffix so it does not overwrite Top 50."""
    suffix = "" if top == 50 else f"_top{top}"
    return (
        OUTPUT_DIR / f"train{suffix}.csv",
        OUTPUT_DIR / f"test{suffix}.csv",
        RESULTS_DIR / f"split_summary{suffix}.txt",
    )

N_FOLDS = 5          # 1 fold for test = 20% test, 80% train (same ratio as before)
SEED = 42

# Only official CWE names with at least this many words count as leakage.
# Shorter names ("Use After Free", "Cross-Site Request Forgery (CSRF)") are the
# normal way people describe these bugs, so they are not leakage.
LEAK_MIN_WORDS = 6

OUTPUT_COLUMNS = ["cve_id", "cve_description", "cwe_id", "year", "leak_flag", "norm_key"]


# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

# "CWE-79", "CWE 79", "(CWE-79)"
CWE_MENTION = re.compile(r"\(?\bCWE[-\s]?\d+\b\)?", re.IGNORECASE)

# Used only to build norm_key (the template key), never to change the description.
URL = re.compile(r"https?://\S+|www\.\S+")
DOUBLE_QUOTED = re.compile(r"[\"“”][^\"“”]{0,200}[\"“”]")
# Single quotes only when not surrounded by letters, so "attacker's" is not a quote.
SINGLE_QUOTED = re.compile(r"(?<![a-z])['‘’][^'‘’]{1,80}['‘’](?![a-z])")
# Standalone numbers and versions only (1.2.3, v4.0, 2024); keeps Win32, sha256.
NUMBER = re.compile(r"\bv?\d+(?:[.\-_]\d+)*\b")


def clean_spaces(text):
    return " ".join(str(text).split())


def remove_cwe_ids(text):
    """Leak 1: drop CWE ID mentions such as 'CWE-79' from the description."""
    return clean_spaces(CWE_MENTION.sub(" ", text))


def make_norm_key(text):
    """
    Leak 3: template key. Two descriptions that differ only in quoted names,
    URLs, numbers or versions get the same key.
    """
    key = text.lower()
    key = URL.sub(" <url> ", key)
    key = DOUBLE_QUOTED.sub(" <q> ", key)
    key = SINGLE_QUOTED.sub(" <q> ", key)
    key = NUMBER.sub("0", key)
    return clean_spaces(key)


def add_leak_flag(df):
    """
    Leak 2: mark descriptions that contain an official CWE name.
    The names come from the cwe_name column of the input file, so only the
    Top-K classes are checked.
    """
    names = (
        df[["cwe_id", "cwe_name"]]
        .drop_duplicates("cwe_id")
        .assign(name_lower=lambda d: d["cwe_name"].str.lower().map(clean_spaces))
    )
    names = names[names["name_lower"].str.split().str.len() >= LEAK_MIN_WORDS]

    text = df["cve_description"].str.lower()
    hits = pd.DataFrame(
        {cid: text.str.contains(name, regex=False) for cid, name in zip(names["cwe_id"], names["name_lower"])},
        index=df.index,
    )

    # Own name found -> 1; another CWE's name found -> 2; nothing -> 0
    own = pd.Series(False, index=df.index)
    for cid in hits.columns:
        own |= hits[cid] & (df["cwe_id"] == cid)
    other = hits.any(axis=1) & ~own

    flag = pd.Series(0, index=df.index)
    flag[other] = 2
    flag[own] = 1
    return flag, len(names)


# ---------------------------------------------------------------------------
# Split
# ---------------------------------------------------------------------------

def grouped_stratified_split(df):
    """
    80/20 split that
      - keeps every norm_key group entirely in train or entirely in test, and
      - keeps the CWE class proportions as close as possible to stratified.
    """
    sgkf = StratifiedGroupKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    train_idx, test_idx = next(sgkf.split(df, y=df["cwe_id"], groups=df["norm_key"]))
    return df.iloc[train_idx].copy(), df.iloc[test_idx].copy()


# ---------------------------------------------------------------------------
# Summary and checks
# ---------------------------------------------------------------------------

class Summary:
    """Print every line and save the same text to split_summary.txt."""

    def __init__(self):
        self.lines = []

    def add(self, line=""):
        print(line)
        self.lines.append(line)

    def save(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        print(f"Summary saved to: {path}")


def leak_share(df):
    shares = df["leak_flag"].value_counts(normalize=True)
    return ", ".join(f"{k}: {shares.get(k, 0):.1%}" for k in (0, 1, 2))


def run_checks(summary, train, test, n_classes):
    failures = []

    def check(label, ok, detail=""):
        summary.add(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" ({detail})" if detail else ""))
        if not ok:
            failures.append(label)

    shared_ids = set(train["cve_id"]) & set(test["cve_id"])
    check("no cve_id in both train and test", not shared_ids, f"{len(shared_ids)} shared")

    shared_keys = set(train["norm_key"]) & set(test["norm_key"])
    check("no template (norm_key) in both train and test", not shared_keys, f"{len(shared_keys)} shared")

    for name, part in [("train", train), ("test", test)]:
        left = int(part["cve_description"].str.contains(r"\bCWE[-\s]?\d+\b", case=False, regex=True).sum())
        check(f"{name}: no CWE IDs left in cve_description", left == 0, f"{left} rows")

        empty = int((part["cve_description"].str.strip() == "").sum())
        check(f"{name}: no empty cve_description", empty == 0, f"{empty} rows")

        n = part["cwe_id"].nunique()
        check(f"{name}: contains all {n_classes} CWE classes", n == n_classes, f"{n} classes")

    test_share = len(test) / (len(train) + len(test))
    check("test share is close to 20%", 0.17 <= test_share <= 0.23, f"{test_share:.1%}")

    return failures


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Leakage-aware train/test split")
    parser.add_argument("--top", type=int, default=50, choices=[25, 50], help="use cve_cwe_top25 or top50")
    args = parser.parse_args()

    input_file = PROCESSED_DIR / f"cve_cwe_top{args.top}.csv"
    train_file, test_file, summary_file = output_files(args.top)
    print(f"Reading: {input_file}")
    df = pd.read_csv(input_file, dtype=str, keep_default_na=False)

    required = ["cve_id", "cve_description", "cwe_id", "cwe_name", "year"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    df = df[df["cve_id"] != ""].drop_duplicates(subset=["cve_id"]).reset_index(drop=True)
    n_classes = df["cwe_id"].nunique()

    # Leak 1: CWE IDs in the text
    had_id = df["cve_description"].str.contains(r"\bCWE[-\s]?\d+\b", case=False, regex=True)
    df["cve_description"] = df["cve_description"].map(remove_cwe_ids)

    # Leak 2: official CWE names in the text (flag only)
    df["leak_flag"], n_names = add_leak_flag(df)

    # Leak 3: template groups
    df["norm_key"] = df["cve_description"].map(make_norm_key)
    group_size = df["norm_key"].map(df["norm_key"].value_counts())

    # Split
    train, test = grouped_stratified_split(df)
    train = train.sort_values("cve_id")[OUTPUT_COLUMNS].reset_index(drop=True)
    test = test.sort_values("cve_id")[OUTPUT_COLUMNS].reset_index(drop=True)

    # Save
    print()
    save_csv(train, train_file)
    save_csv(test, test_file)

    # Summary
    s = Summary()
    s.add()
    s.add("=" * 70)
    s.add(f"Leakage-aware split (Top {args.top})")
    s.add("=" * 70)
    s.add(f"Input rows:                         {len(df):,}")
    s.add(f"CWE classes:                        {n_classes}")
    s.add()
    s.add(f"Leak 1 - CWE IDs removed from text: {int(had_id.sum()):,} rows")
    s.add(f"Leak 2 - official name in text:     {int((df['leak_flag'] == 1).sum()):,} rows own CWE, "
          f"{int((df['leak_flag'] == 2).sum()):,} rows other CWE "
          f"(checked {n_names} names with >= {LEAK_MIN_WORDS} words)")
    s.add(f"Leak 3 - rows in a template group:  {int((group_size > 1).sum()):,} rows "
          f"in {int((df['norm_key'].value_counts() > 1).sum()):,} groups, largest {int(group_size.max()):,}")
    s.add()
    s.add(f"Train rows: {len(train):,}   Test rows: {len(test):,}   ({len(test) / len(df):.1%} test)")
    s.add(f"leak_flag share  train -> {leak_share(train)}")
    s.add(f"leak_flag share  test  -> {leak_share(test)}")
    s.add(f"Clean test rows (leak_flag = 0): {int((test['leak_flag'] == 0).sum()):,}")

    smallest = test["cwe_id"].value_counts().nsmallest(3)
    s.add("Smallest test classes: " + ", ".join(f"{k} ({v})" for k, v in smallest.items()))
    s.add()

    s.add("Checks")
    failures = run_checks(s, train, test, n_classes)
    s.add()
    s.add(f"{len(failures)} check(s) FAILED: {failures}" if failures else "All checks passed. Split complete.")
    s.save(summary_file)

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
