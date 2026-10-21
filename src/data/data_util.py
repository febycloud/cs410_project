#通用的function可以写在这里被其他python引用
from pathlib import Path
import os
import pandas as pd


# Allow override with environment variable.
# Default path on our shared VM is /home/data.
DATA_ROOT = Path(os.getenv("DATA_ROOT", "/home/data"))

RAW_DIR = DATA_ROOT / "raw"
PROCESSED_DIR = DATA_ROOT / "processed"

NVD_DIR = RAW_DIR / "nvd"
CWE_DIR = RAW_DIR / "cwe"

CWE_RAW_FILE = CWE_DIR / "CWE_comprehensive_view.csv"

CVE_CLEAN_FILE = PROCESSED_DIR / "cve_clean.csv"
CWE_CLEAN_FILE = PROCESSED_DIR / "cwe_clean.csv"


def ensure_directories():
    """
    Make sure processed data directory exists.
    Raw data will never be modified.
    """
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def normalize_cwe_id(value):
    """
    Convert different CWE ID formats into CWE-<number>.

    Examples:
        22      -> CWE-22
        "22"    -> CWE-22
        "CWE-22" -> CWE-22
    """
    if pd.isna(value):
        return None

    value = str(value).strip()

    if not value:
        return None

    if value.upper().startswith("CWE-"):
        number = value.split("-", 1)[1]
    else:
        number = value

    number = number.strip()

    if not number.isdigit():
        return None

    return f"CWE-{int(number)}"


def clean_text(value):
    """
    Basic text cleaning without changing the meaning.
    Removes extra whitespace and line breaks.
    """
    if pd.isna(value):
        return ""

    return " ".join(str(value).split())


def save_csv(df, path):
    """
    Save dataframe as UTF-8 CSV.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False, encoding="utf-8")

    print(f"Saved {len(df):,} rows to:")
    print(path)