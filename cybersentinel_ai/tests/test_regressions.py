"""Regression tests for API, temporal detection and persistence failures."""
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

from cybersentinel_ai import (
    AnomalyDetector, AttackGraphBuilder, Config, CorrelationEngine, CyberSentinelAI,
    EventSource, EventType, FeatureEngineer, LogGenerator, RiskEngine, RuleEngine,
    SecurityEvent, analyze_events, analyze_events_from_dicts,
)
from cybersentinel_ai.core.indicators import is_external_ip

BASE = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)


def event(kind=EventType.FAILED_LOGIN, minute=0, **kwargs):
    values = dict(timestamp=BASE + timedelta(minutes=minute), source=EventSource.AUTHENTICATION,
                  event_type=kind, user="alice", device="host-a", source_ip="185.20.30.1")
    values.update(kwargs)
    return SecurityEvent(**values)


class TestRegressions(unittest.TestCase):
    def test_demo_rules_across_seeds(self):
        expected = {"brute_force": "brute_force", "account_compromise": "account_compromise",
                    "data_exfiltration": "data_exfiltration", "coordinated_attack": "coordinated_attack"}
        for seed in range(10):
            for scenario, rule_type in expected.items():
                with self.subTest(seed=seed, scenario=scenario):
                    events = LogGenerator(seed=seed).generate_scenario(scenario, BASE)
                    self.assertIn(rule_type, {m.rule_type.value for m in RuleEngine().evaluate(events)})

    def test_mitre_correct_ids_and_no_generic_process_mapping(self):
        from cybersentinel_ai.mitre import MitreMapper
        mapper = MitreMapper()
        self.assertNotIn("T1005.001", mapper.techniques)
        self.assertEqual(mapper.techniques["T1550.002"]["name"], "Pass the Hash")
        benign = event(EventType.PROCESS_EXECUTION, source=EventSource.ENDPOINT,
                       metadata={"process_name": "notepad.exe"})
        self.assertEqual(mapper.map_events([benign]), [])

    def test_all_scenarios_json_serializable(self):
        for scenario in ("normal_activity", "brute_force", "account_compromise", "data_exfiltration", "coordinated_attack"):
            with self.subTest(scenario=scenario):
                events = LogGenerator(seed=17).generate_scenario(scenario, BASE)
                result = analyze_events_from_dicts([e.to_dict() for e in events])
                decoded = json.loads(json.dumps(result, allow_nan=False))
                self.assertEqual(decoded["statistics"]["total_events"], len(events))
                self.assertEqual(sum(decoded["statistics"]["rule_matches_by_type"].values()),
                                 decoded["statistics"]["rule_match_count"])
                if scenario == "normal_activity":
                    self.assertEqual(decoded["incidents"], [])
                    self.assertEqual(decoded["mitre_techniques"], [])

    def test_event_roundtrip_preserves_id_and_normalizes_time(self):
        original = event(timestamp="2026-01-15T17:30:00+05:30")
        restored = SecurityEvent.from_dict(original.to_dict())
        self.assertEqual(original, restored)
        self.assertEqual(restored.timestamp, BASE)
        self.assertNotEqual(event().event_id, event().event_id)
        analyze_events([restored, event(timestamp=datetime(2026, 1, 15, 12))])

    def test_bad_metadata_rejected(self):
        for metadata in (None, [], {"bytes_sent": "100"}, {"bytes_sent": float("nan")}, {"bytes_received": -1}):
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                event(metadata=metadata)

    def test_features_do_not_use_future_events(self):
        first, future = event(), event(minute=10)
        engineer = FeatureEngineer()
        alone = engineer.extract_features([first])[0].features
        combined = engineer.extract_features([first, future])[0].features
        self.assertEqual(alone, combined)
        self.assertEqual(combined["failed_login_count"], 1)

    def test_empty_feature_window(self):
        features = FeatureEngineer().extract_features([event()], BASE - timedelta(days=1))[0].features
        self.assertEqual(features["failed_login_count"], 0)
        self.assertEqual(features["time_span_minutes"], 0)

    def test_brute_force_ignores_old_noise(self):
        burst = [event(minute=i) for i in range(5)]
        burst += [event(EventType.SUCCESSFUL_LOGIN, 5)]
        matches = RuleEngine().evaluate([event(minute=-120)] + burst)
        brute = [m for m in matches if m.rule_type.value == "brute_force"]
        self.assertEqual(len(brute), 1)
        self.assertEqual(brute[0].evidence["failed_count"], 5)

    def test_brute_force_success_must_follow_and_be_recent(self):
        failures = [event(minute=i) for i in range(5)]
        for minute in (-1, 120):
            matches = RuleEngine().evaluate(failures + [event(EventType.SUCCESSFUL_LOGIN, minute)])
            self.assertFalse(any(m.rule_type.value == "brute_force" for m in matches))

    def test_brute_force_optional_success(self):
        config = Config.from_dict({"rules": {"brute_force_require_success": False}})
        matches = RuleEngine(config).evaluate([event(minute=i) for i in range(5)])
        self.assertEqual(matches[0].severity.value, "MEDIUM")

    def test_exfiltration_requires_recent_preceding_access(self):
        access = event(EventType.FILE_ACCESS, source=EventSource.ENDPOINT, metadata={"file_path": "/etc/shadow"})
        for minute, expected in ((30, True), (90, False), (-10, False)):
            transfer = event(EventType.DATA_TRANSFER, minute, source=EventSource.NETWORK,
                             destination_ip="185.20.30.2", metadata={"bytes_sent": 200 * 1024 * 1024})
            matches = RuleEngine().evaluate([access, transfer])
            self.assertEqual(any(m.rule_type.value == "data_exfiltration" for m in matches), expected)

    def test_account_compromise_window_and_flags(self):
        login = event(EventType.SUCCESSFUL_LOGIN, metadata={"is_new_ip": True, "is_unusual_time": True})
        escalation = event(EventType.PRIVILEGE_ESCALATION, 60)
        self.assertTrue(any(m.rule_type.value == "account_compromise" for m in RuleEngine().evaluate([login, escalation])))
        config = Config.from_dict({"rules": {"account_compromise_time_window_hours": 0.5}})
        self.assertFalse(any(m.rule_type.value == "account_compromise" for m in RuleEngine(config).evaluate([login, escalation])))
        config = Config.from_dict({"rules": {"account_compromise_privilege_escalation": False}})
        self.assertTrue(any(m.rule_type.value == "account_compromise" for m in RuleEngine(config).evaluate([login])))

    def test_powershell_does_not_use_future_authentication(self):
        ps = event(EventType.POWERSHELL_EXECUTION, source=EventSource.ENDPOINT, metadata={"command": "powershell -enc example"})
        self.assertEqual(RuleEngine().evaluate([ps, event(minute=10)]), [])

    def test_unrelated_sources_do_not_form_coordinated_attack(self):
        auth = event()
        endpoint = event(EventType.SUSPICIOUS_PROCESS, source=EventSource.ENDPOINT, user="bob", device="host-b")
        network = event(EventType.DATA_TRANSFER, source=EventSource.NETWORK, user="carol", device="host-c",
                        metadata={"bytes_sent": 200 * 1024 * 1024})
        self.assertFalse(any(m.rule_type.value == "coordinated_attack" for m in RuleEngine().evaluate([auth, endpoint, network])))

    def test_normal_activity_has_no_attack_chains(self):
        events = LogGenerator(seed=7).generate_normal_activity(300, BASE)
        self.assertEqual(CorrelationEngine().correlate(events, []), [])

    def test_chain_bounds_and_graph_deduplication(self):
        events = LogGenerator(seed=42).generate_coordinated_attack(BASE)
        config = Config.from_dict({"correlation": {"max_chain_length": 7}})
        chains = CorrelationEngine(config).correlate(events, RuleEngine().evaluate(events))
        self.assertTrue(chains)
        for chain in chains:
            self.assertLessEqual(len(chain.events), 7)
            self.assertTrue(0 <= chain.correlation_score <= 1)
            self.assertEqual(chain.end_time, chain.events[-1].event.timestamp)
        graph = AttackGraphBuilder().build_from_chains([chains[0], chains[0]])
        single = AttackGraphBuilder().build_from_chain(chains[0])
        self.assertEqual(len(graph.edges), len(single.edges))
        self.assertEqual(graph.metadata["total_events"], len(chains[0].events))

    def test_severity_boundaries(self):
        engine = RiskEngine()
        for score, expected in ((0, "LOW"), (30, "LOW"), (31, "MEDIUM"), (60, "MEDIUM"),
                                (61, "HIGH"), (80, "HIGH"), (81, "CRITICAL"), (100, "CRITICAL")):
            self.assertEqual(engine._determine_severity(score).value, expected)

    def test_config_isolation_and_validation(self):
        first, second = CyberSentinelAI(), CyberSentinelAI()
        first.config.rules.brute_force_failed_attempts = 100
        self.assertEqual(second.config.rules.brute_force_failed_attempts, 5)
        exported = second.config.to_dict()
        exported["risk"]["severity_thresholds"]["LOW"] = 1
        self.assertEqual(second.config.risk.severity_thresholds["LOW"], 30)
        for data in ({"ml": {"contamination": 0}}, {"correlation": {"max_chain_length": 0}},
                     {"rules": {"brute_force_time_window_minutes": -1}}):
            with self.assertRaises(ValueError):
                Config.from_dict(data)

    def test_external_ip_ipv4_ipv6_and_invalid(self):
        for address in ("10.0.0.1", "172.16.0.1", "192.168.0.1", "::1", "fc00::1", "bad", "999.2.3.4"):
            self.assertFalse(is_external_ip(address))
        self.assertTrue(is_external_ip("2606:4700:4700::1111"))


class TestModelRegressions(unittest.TestCase):
    def test_command_line_demo_returns_json(self):
        completed = subprocess.run([sys.executable, "-m", "cybersentinel_ai", "--full"],
                                   cwd=Path(__file__).resolve().parents[2], capture_output=True,
                                   text=True, check=True, timeout=60)
        result = json.loads(completed.stdout)
        self.assertEqual(result["statistics"]["severity"], "CRITICAL")
        self.assertEqual(result["incidents"][0]["attack_type"], "Coordinated Attack")

    @classmethod
    def setUpClass(cls):
        cls.config = Config.from_dict({"ml": {"feature_window_minutes": 15, "anomaly_threshold": 0.55}})
        cls.detector = AnomalyDetector(cls.config)
        cls.detector.train(LogGenerator(seed=42).generate_normal_activity(200, BASE))

    def test_single_prediction_uses_fitted_score(self):
        e = event()
        single = self.detector.predict_single(e)
        paired = self.detector.predict([e, event(minute=120)])[0]
        self.assertAlmostEqual(single.normalized_score, paired.normalized_score)
        self.assertAlmostEqual(single.normalized_score, max(0, min(1, 0.5 - single.raw_score)))

    def test_save_load_preserves_configuration_and_predictions(self):
        events = LogGenerator(seed=9).generate_brute_force(BASE)
        before = self.detector.predict(events)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "model.pkl")
            self.detector.save(path)
            restored = AnomalyDetector().load(path)
            after = restored.predict(events)
        self.assertEqual(restored.config.to_dict(), self.config.to_dict())
        self.assertEqual([r.normalized_score for r in before], [r.normalized_score for r in after])

    def test_empty_analysis_keeps_training_status(self):
        engine = CyberSentinelAI()
        engine.anomaly_detector = self.detector
        result = engine.analyze_events([])
        self.assertTrue(result["statistics"]["ml_trained"])
        self.assertEqual(result["incidents"], [])

    def test_trained_output_json_and_event_links(self):
        engine = CyberSentinelAI()
        engine.anomaly_detector = self.detector
        events = LogGenerator(seed=3).generate_brute_force(BASE)
        result = engine.analyze_events(events)
        json.dumps(result, allow_nan=False)
        self.assertEqual({a["event_id"] for a in result["anomalies"]}, {e.event_id for e in events})


if __name__ == "__main__":
    unittest.main()
