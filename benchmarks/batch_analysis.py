"""Reproduce the local synthetic batch timing: python benchmarks/batch_analysis.py."""
from datetime import datetime, timezone
from pathlib import Path
import sys
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cybersentinel_ai import FeatureEngineer, LogGenerator, RuleEngine


def main():
    events = LogGenerator(seed=42).generate_normal_activity(
        3000, datetime(2026, 1, 15, tzinfo=timezone.utc))
    for name, operation in (("features", FeatureEngineer().extract_features),
                            ("rules", RuleEngine().evaluate)):
        start = perf_counter()
        operation(events)
        print(f"{name}: {perf_counter() - start:.3f} seconds (3000 events)")


if __name__ == "__main__":
    main()
