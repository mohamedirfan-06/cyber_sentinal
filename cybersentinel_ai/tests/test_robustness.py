"""Input, persistence and bounded-correlation regression coverage."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

import joblib
from cybersentinel_ai import (
    AnomalyDetector, Config, CorrelationEngine, CyberSentinelAI, EventSource,
    EventType, FeatureEngineer, LogGenerator, RuleEngine, SecurityEvent,
)

BASE = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)


class TestInputRobustness(unittest.TestCase):
    def test_mitre_keeps_strongest_duplicate_and_all_evidence(self):
        from dataclasses import replace
        from cybersentinel_ai.mitre import MitreMapper
        events = LogGenerator(seed=42).generate_brute_force(BASE)
        match = RuleEngine().evaluate(events)[0]
        weaker = replace(match, confidence=0.2, description="weak evidence")
        stronger = replace(match, confidence=0.95, description="strong evidence")
        for matches in ([weaker, stronger], [stronger, weaker]):
            techniques = MitreMapper().map_rule_matches(matches)
            self.assertTrue(techniques)
            for technique in techniques:
                self.assertEqual(technique.confidence, 0.95)
                self.assertEqual(set(technique.evidence), {"weak evidence", "strong evidence"})
                self.assertEqual(set(technique.event_ids), {e.event_id for e in events})

    def test_mitre_output_links_to_input_events(self):
        events = LogGenerator(seed=42).generate_coordinated_attack(BASE)
        result = CyberSentinelAI().analyze_events(events)
        self.assertTrue(result["mitre_techniques"])
        valid_ids = {e.event_id for e in events}
        for technique in result["mitre_techniques"]:
            self.assertTrue(technique["event_ids"])
            self.assertLessEqual(set(technique["event_ids"]), valid_ids)

    def test_reject_invalid_config_values(self):
        cases = [
            {"ml": {"n_estimators": 1.5}}, {"ml": {"feature_window_minutes": float("nan")}},
            {"ml": {"max_samples": 0}}, {"ml": {"random_state": -1}},
            {"correlation": {"max_chain_length": 2.5}}, {"correlation": {"correlation_keys": ["typo"]}},
            {"risk": {"ml_weight": float("inf")}}, {"risk": {"rule_weight": float("nan")}},
            {"rules": {"brute_force_require_success": "false"}},
            {"rules": {"brute_force_time_window_minutes": float("nan")}},
            {"rules": {"brute_force_failed_attempts": True}}, {"typo": {}}, {"ml": None},
        ]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                Config.from_dict(values)

    def test_config_does_not_alias_input(self):
        values = Config().to_dict()
        config = Config.from_dict(values)
        values["risk"]["severity_thresholds"]["LOW"] = 1
        values["correlation"]["correlation_keys"].clear()
        self.assertEqual(config.risk.severity_thresholds["LOW"], 30)
        self.assertTrue(config.correlation.correlation_keys)

    def test_invalid_entity_and_metadata_fields(self):
        base = dict(timestamp=BASE, source="network", event_type="connection")
        cases = [{"user": []}, {"port": True}, {"port": 65536}, {"is_demo": "false"},
                 {"metadata": {"process_name": []}}, {"metadata": {"is_new_ip": "false"}},
                 {"metadata": {"nested": [float("nan")]}}, {"raw_event": {"time": BASE}}]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                SecurityEvent(**base, **values)

    def test_z_timestamp_and_duplicate_event_ids(self):
        original = SecurityEvent.from_dict(dict(timestamp="2026-01-15T12:00:00Z",
                                               source="network", event_type="connection"))
        self.assertEqual(original.timestamp, BASE)
        clone = SecurityEvent.from_dict(original.to_dict())
        with self.assertRaisesRegex(ValueError, "unique event_id"):
            CyberSentinelAI().analyze_events([original, clone])

    def test_indexed_features_match_explicit_windows(self):
        events = LogGenerator(seed=5).generate_normal_activity(50, BASE)
        # Include exact boundaries and duplicate timestamps; preserve caller order.
        events += [SecurityEvent(BASE + timedelta(minutes=m), EventSource.AUTHENTICATION,
                                 EventType.FAILED_LOGIN) for m in (0, 0, 60, 61)]
        events.reverse()
        engineer = FeatureEngineer()
        actual = engineer.extract_features(events)
        for target, vector in zip(events, actual):
            window = [e for e in events if target.timestamp - timedelta(minutes=60) <= e.timestamp <= target.timestamp]
            expected = engineer.extract_features(window)
            index = next(i for i, e in enumerate(window) if e.event_id == target.event_id)
            self.assertEqual(vector.features, expected[index].features)
            self.assertIs(vector.event, target)

    def test_bounded_chains_preserve_final_success(self):
        events = LogGenerator(seed=42).generate_brute_force(BASE)
        config = Config.from_dict({"correlation": {"max_chain_length": 3}})
        chains = CorrelationEngine(config).correlate(events, RuleEngine().evaluate(events))
        self.assertEqual({ce.event.event_id for c in chains for ce in c.events}, {e.event_id for e in events})
        for chain in chains:
            self.assertLessEqual(len(chain.events), 3)
            self.assertEqual([ce.sequence_number for ce in chain.events], list(range(len(chain.events))))
            self.assertEqual(chain.start_time, chain.events[0].event.timestamp)
            self.assertEqual(chain.end_time, chain.events[-1].event.timestamp)


class TestPersistenceFailures(unittest.TestCase):
    def setUp(self):
        self.events = LogGenerator(seed=3).generate_normal_activity(30, BASE)
        self.detector = AnomalyDetector(Config.from_dict({"ml": {"n_estimators": 10}}))
        self.detector.train(self.events)

    def test_failed_retrain_preserves_previous_model(self):
        before = self.detector.predict(self.events)
        model, scaler = self.detector.model, self.detector.scaler
        with patch("cybersentinel_ai.ml.anomaly_detector.IsolationForest.fit", side_effect=ValueError("fit failed")):
            with self.assertRaisesRegex(ValueError, "fit failed"):
                self.detector.train(self.events)
        self.assertIs(self.detector.model, model)
        self.assertIs(self.detector.scaler, scaler)
        self.assertEqual([r.raw_score for r in before], [r.raw_score for r in self.detector.predict(self.events)])

    def test_same_model_scaler_path_does_not_overwrite_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "existing.pkl"
            target.write_bytes(b"preserve existing file")
            with self.assertRaisesRegex(ValueError, "paths must be different"):
                self.detector.save(str(target), str(target))
            self.assertEqual(target.read_bytes(), b"preserve existing file")

    def test_bad_saved_model_preserves_previous_state(self):
        model, scaler = self.detector.model, self.detector.scaler
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.pkl"
            joblib.dump({"model": "invalid"}, path)
            joblib.dump(scaler, path.with_suffix(".scaler.pkl"))
            with self.assertRaises(ValueError):
                self.detector.load(str(path))
        self.assertIs(self.detector.model, model)
        self.assertIs(self.detector.scaler, scaler)
        self.assertEqual(len(self.detector.predict(self.events)), len(self.events))

    def test_all_cli_scenarios(self):
        import subprocess
        import sys
        for scenario in ("normal_activity", "brute_force", "account_compromise", "data_exfiltration"):
            with self.subTest(scenario=scenario):
                run = subprocess.run([sys.executable, "-m", "cybersentinel_ai", "--scenario", scenario, "--full"],
                                     capture_output=True, text=True, timeout=60, check=True,
                                     cwd=Path(__file__).resolve().parents[2])
                result = json.loads(run.stdout)
                self.assertTrue(result["statistics"]["ml_trained"])
                self.assertEqual(bool(result["incidents"]), scenario != "normal_activity")


if __name__ == "__main__":
    unittest.main()
