"""Run an offline synthetic demonstration: python -m cybersentinel_ai."""
import argparse
import json
from datetime import datetime, timedelta, timezone

from . import CyberSentinelAI, LogGenerator


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", default="coordinated_attack", choices=[
        "normal_activity", "brute_force", "account_compromise", "data_exfiltration", "coordinated_attack",
    ])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--full", action="store_true", help="Print complete JSON results")
    args = parser.parse_args()
    base = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)
    generator = LogGenerator(seed=args.seed)
    engine = CyberSentinelAI()
    engine.train_anomaly_detector(generator.generate_normal_activity(300, base - timedelta(days=1)))
    result = engine.analyze_events(generator.generate_scenario(args.scenario, base))
    print(json.dumps(result if args.full else result["statistics"], indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
