"""Backward-compatible entry point for the canonical Step 2 validator."""

try:
    from .validate_step2 import main
except ImportError:
    from validate_step2 import main


if __name__ == "__main__":
    main()
