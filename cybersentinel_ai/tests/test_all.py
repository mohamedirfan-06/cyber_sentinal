"""Comprehensive tests for the CyberSentinel AI module."""

import unittest
from datetime import datetime, timedelta, timezone

from cybersentinel_ai import (
    LogGenerator,
    SecurityEvent,
    EventSource,
    EventType,
    Action,
    FeatureEngineer,
    AnomalyDetector,
    RuleEngine,
    CorrelationEngine,
    AttackGraphBuilder,
    RiskEngine,
    Incident,
    CyberSentinelAI,
    analyze_events,
    analyze_events_from_dicts,
    Config,
    DEFAULT_CONFIG,
)
from cybersentinel_ai.core.schemas import FeatureVector


class TestLogGenerator(unittest.TestCase):
    """Tests for the demo log generator."""
    
    def setUp(self):
        self.generator = LogGenerator(seed=42)
        self.base_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    def test_normal_activity(self):
        events = self.generator.generate_normal_activity(50, self.base_time)
        self.assertEqual(len(events), 50)
        self.assertTrue(all(e.is_demo for e in events))
        self.assertTrue(all(e.timestamp >= self.base_time for e in events))
    
    def test_brute_force(self):
        events = self.generator.generate_brute_force(self.base_time)
        self.assertGreater(len(events), 15)  # 15+ failed + 1 success
        
        failed = [e for e in events if e.event_type == EventType.FAILED_LOGIN]
        success = [e for e in events if e.event_type == EventType.SUCCESSFUL_LOGIN]
        
        self.assertGreaterEqual(len(failed), 15)
        self.assertEqual(len(success), 1)
        
        # All from same IP and user
        ips = set(e.source_ip for e in failed)
        users = set(e.user for e in failed)
        self.assertEqual(len(ips), 1)
        self.assertEqual(len(users), 1)
    
    def test_account_compromise(self):
        events = self.generator.generate_account_compromise(self.base_time)
        
        # Check sequence: normal login -> unusual login -> privilege esc -> powershell -> file access
        event_types = [e.event_type for e in events]
        
        self.assertIn(EventType.SUCCESSFUL_LOGIN, event_types)
        self.assertIn(EventType.PRIVILEGE_ESCALATION, event_types)
        self.assertIn(EventType.POWERSHELL_EXECUTION, event_types)
        self.assertIn(EventType.FILE_ACCESS, event_types)
    
    def test_data_exfiltration(self):
        events = self.generator.generate_data_exfiltration(self.base_time)
        
        file_access = [e for e in events if e.event_type == EventType.FILE_ACCESS]
        transfers = [e for e in events if e.event_type == EventType.DATA_TRANSFER]
        
        self.assertGreater(len(file_access), 0)
        self.assertEqual(len(transfers), 1)
        
        # Check large transfer
        transfer = transfers[0]
        self.assertGreater(transfer.metadata.get("bytes_sent", 0), 100 * 1024 * 1024)
    
    def test_coordinated_attack(self):
        events = self.generator.generate_coordinated_attack(self.base_time)
        
        # Verify required sequence
        event_types = [e.event_type for e in events]
        
        # 17 failed logins
        failed_count = sum(1 for e in events if e.event_type == EventType.FAILED_LOGIN)
        self.assertEqual(failed_count, 17)
        
        # 1 successful login (first IP)
        success_1 = [e for e in events if e.event_type == EventType.SUCCESSFUL_LOGIN and e.source_ip == events[0].source_ip]
        self.assertEqual(len(success_1), 1)
        
        # New source IP successful login
        success_2 = [e for e in events if e.event_type == EventType.SUCCESSFUL_LOGIN and e.source_ip != events[0].source_ip]
        self.assertEqual(len(success_2), 1)
        
        # Privilege escalation
        self.assertIn(EventType.PRIVILEGE_ESCALATION, event_types)
        
        # PowerShell execution (multiple)
        ps_count = sum(1 for e in events if e.event_type == EventType.POWERSHELL_EXECUTION)
        self.assertGreaterEqual(ps_count, 3)
        
        # Sensitive file access
        file_access = [e for e in events if e.event_type == EventType.FILE_ACCESS]
        self.assertGreaterEqual(len(file_access), 3)
        
        # Large outbound transfer
        transfers = [e for e in events if e.event_type == EventType.DATA_TRANSFER]
        self.assertEqual(len(transfers), 1)
        self.assertGreater(transfers[0].metadata.get("bytes_sent", 0), 200 * 1024 * 1024)
    
    def test_generate_scenario(self):
        for scenario in ["normal_activity", "brute_force", "account_compromise", "data_exfiltration", "coordinated_attack"]:
            events = self.generator.generate_scenario(scenario, self.base_time)
            self.assertGreater(len(events), 0)
            self.assertTrue(all(e.is_demo for e in events))
    
    def test_invalid_scenario(self):
        with self.assertRaises(ValueError):
            self.generator.generate_scenario("invalid_scenario", self.base_time)


class TestFeatureEngineer(unittest.TestCase):
    """Tests for feature engineering."""
    
    def setUp(self):
        self.generator = LogGenerator(seed=42)
        self.engineer = FeatureEngineer()
        self.base_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    def test_extract_features_normal(self):
        events = self.generator.generate_normal_activity(20, self.base_time)
        vectors = self.engineer.extract_features(events)
        
        self.assertEqual(len(vectors), 20)
        self.assertTrue(all(isinstance(v, FeatureVector) for v in vectors))
        self.assertEqual(len(vectors[0].features), len(self.engineer.FEATURE_NAMES))
    
    def test_extract_features_attack(self):
        events = self.generator.generate_brute_force(self.base_time)
        vectors = self.engineer.extract_features(events)
        
        self.assertEqual(len(vectors), len(events))
        
        # Check that failed_login_count feature is populated
        for v in vectors:
            self.assertIn("failed_login_count", v.features)
    
    def test_feature_matrix(self):
        events = self.generator.generate_normal_activity(10, self.base_time)
        matrix = self.engineer.get_feature_matrix(events)
        
        self.assertEqual(len(matrix), 10)
        self.assertEqual(len(matrix[0]), len(self.engineer.FEATURE_NAMES))
    
    def test_feature_names_order(self):
        names = self.engineer.get_feature_names()
        self.assertEqual(len(names), len(self.engineer.FEATURE_NAMES))
        self.assertEqual(names, self.engineer.FEATURE_NAMES)


class TestAnomalyDetector(unittest.TestCase):
    """Tests for ML anomaly detection."""
    
    def setUp(self):
        self.generator = LogGenerator(seed=42)
        self.detector = AnomalyDetector()
        self.base_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    def test_train_and_predict_normal(self):
        # Train on normal activity
        normal_events = self.generator.generate_normal_activity(200, self.base_time)
        self.detector.train(normal_events)
        
        self.assertTrue(self.detector.is_trained)
        
        # Predict on normal events
        test_events = self.generator.generate_normal_activity(20, self.base_time + timedelta(hours=1))
        results = self.detector.predict(test_events)
        
        self.assertEqual(len(results), 20)
        self.assertTrue(all(isinstance(r.normalized_score, float) for r in results))
        self.assertTrue(all(0 <= r.normalized_score <= 1 for r in results))
    
    def test_predict_attack_after_training(self):
        # Train on normal
        normal_events = self.generator.generate_normal_activity(200, self.base_time)
        self.detector.train(normal_events)
        
        # Predict on attack
        attack_events = self.generator.generate_brute_force(self.base_time + timedelta(hours=2))
        results = self.detector.predict(attack_events)
        
        # Attack events should have higher anomaly scores
        anomaly_scores = [r.normalized_score for r in results]
        max_score = max(anomaly_scores)
        
        # At least some events should be flagged as anomalous
        self.assertGreater(max_score, 0.3)
    
    def test_predict_without_training_raises(self):
        events = self.generator.generate_normal_activity(10, self.base_time)
        with self.assertRaises(RuntimeError):
            self.detector.predict(events)
    
    def test_save_load(self):
        import tempfile
        import os
        
        normal_events = self.generator.generate_normal_activity(100, self.base_time)
        self.detector.train(normal_events)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = os.path.join(tmpdir, "model.pkl")
            self.detector.save(model_path)
            
            # Load into new detector
            new_detector = AnomalyDetector()
            new_detector.load(model_path)
            
            self.assertTrue(new_detector.is_trained)
            
            # Predict should work
            test_events = self.generator.generate_normal_activity(5, self.base_time)
            results = new_detector.predict(test_events)
            self.assertEqual(len(results), 5)


class TestRuleEngine(unittest.TestCase):
    """Tests for deterministic rule engine."""
    
    def setUp(self):
        self.generator = LogGenerator(seed=42)
        self.engine = RuleEngine()
        self.base_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    def test_brute_force_detection(self):
        events = self.generator.generate_brute_force(self.base_time)
        matches = self.engine.evaluate(events)
        
        brute_force_matches = [m for m in matches if m.rule_type.value == "brute_force"]
        self.assertEqual(len(brute_force_matches), 1)
        
        match = brute_force_matches[0]
        self.assertEqual(match.severity.value, "HIGH")  # Has successful login
        self.assertGreater(match.confidence, 0.8)
        self.assertEqual(match.evidence["failed_count"], 17)
    
    def test_account_compromise_detection(self):
        events = self.generator.generate_account_compromise(self.base_time)
        matches = self.engine.evaluate(events)
        
        ac_matches = [m for m in matches if m.rule_type.value == "account_compromise"]
        self.assertEqual(len(ac_matches), 1)
        
        match = ac_matches[0]
        self.assertIn(match.severity.value, ["HIGH", "CRITICAL"])
        self.assertGreater(match.evidence["indicators_present"], 1)
    
    def test_suspicious_powershell_detection(self):
        events = self.generator.generate_account_compromise(self.base_time)
        matches = self.engine.evaluate(events)
        
        ps_matches = [m for m in matches if m.rule_type.value == "suspicious_powershell"]
        self.assertGreaterEqual(len(ps_matches), 1)
    
    def test_data_exfiltration_detection(self):
        events = self.generator.generate_data_exfiltration(self.base_time)
        matches = self.engine.evaluate(events)
        
        exfil_matches = [m for m in matches if m.rule_type.value == "data_exfiltration"]
        self.assertEqual(len(exfil_matches), 1)
        
        match = exfil_matches[0]
        self.assertIn(match.severity.value, ["HIGH", "CRITICAL"])
        self.assertGreater(match.evidence["total_bytes_sent"], 100 * 1024 * 1024)
    
    def test_coordinated_attack_detection(self):
        events = self.generator.generate_coordinated_attack(self.base_time)
        matches = self.engine.evaluate(events)
        
        coord_matches = [m for m in matches if m.rule_type.value == "coordinated_attack"]
        self.assertEqual(len(coord_matches), 1)
        
        match = coord_matches[0]
        self.assertEqual(match.severity.value, "CRITICAL")
        self.assertGreater(match.confidence, 0.9)
    
    def test_normal_activity_no_matches(self):
        events = self.generator.generate_normal_activity(50, self.base_time)
        matches = self.engine.evaluate(events)
        
        # Should have no or very few matches
        high_severity = [m for m in matches if m.severity.value in ["HIGH", "CRITICAL"]]
        self.assertEqual(len(high_severity), 0)


class TestCorrelationEngine(unittest.TestCase):
    """Tests for event correlation."""
    
    def setUp(self):
        self.generator = LogGenerator(seed=42)
        self.engine = CorrelationEngine()
        self.rule_engine = RuleEngine()
        self.base_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    def test_correlate_coordinated_attack(self):
        events = self.generator.generate_coordinated_attack(self.base_time)
        rule_matches = self.rule_engine.evaluate(events)
        chains = self.engine.correlate(events, rule_matches)
        
        self.assertGreater(len(chains), 0)
        
        # Should find the coordinated attack chain
        coord_chains = [c for c in chains if "coordinated" in c.attack_type.lower() or c.correlation_score > 0.7]
        self.assertGreater(len(coord_chains), 0)
        
        chain = coord_chains[0]
        self.assertGreaterEqual(len(chain.events), 7)  # At least 7 steps in coordinated attack
        self.assertGreater(chain.correlation_score, 0.5)
    
    def test_correlate_brute_force(self):
        events = self.generator.generate_brute_force(self.base_time)
        rule_matches = self.rule_engine.evaluate(events)
        chains = self.engine.correlate(events, rule_matches)
        
        self.assertGreater(len(chains), 0)
        
        # Should find brute force chain
        bf_chains = [c for c in chains if "brute" in c.attack_type.lower()]
        self.assertGreater(len(bf_chains), 0)
    
    def test_empty_events(self):
        chains = self.engine.correlate([], [])
        self.assertEqual(len(chains), 0)


class TestAttackGraph(unittest.TestCase):
    """Tests for attack graph representation."""
    
    def setUp(self):
        self.generator = LogGenerator(seed=42)
        self.base_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    def test_build_graph_from_events(self):
        events = self.generator.generate_coordinated_attack(self.base_time)
        builder = AttackGraphBuilder()
        graph = builder.build_from_events(events)
        
        self.assertGreater(len(graph.nodes), 0)
        self.assertGreater(len(graph.edges), 0)
        
        # Check node types
        node_types = set(n.node_type for n in graph.nodes)
        self.assertIn("ip", node_types)
        self.assertIn("user", node_types)
        self.assertIn("device", node_types)
    
    def test_graph_to_dict(self):
        events = self.generator.generate_brute_force(self.base_time)
        builder = AttackGraphBuilder()
        graph = builder.build_from_events(events)
        
        graph_dict = graph.to_dict()
        self.assertIn("graph_id", graph_dict)
        self.assertIn("nodes", graph_dict)
        self.assertIn("edges", graph_dict)
        
        # Check cytoscape format
        cyto = graph.to_cytoscape()
        self.assertIn("nodes", cyto)
        self.assertIn("edges", cyto)


class TestRiskEngine(unittest.TestCase):
    """Tests for risk scoring."""
    
    def setUp(self):
        self.generator = LogGenerator(seed=42)
        self.engine = RiskEngine()
        self.base_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    def test_normal_activity_low_risk(self):
        events = self.generator.generate_normal_activity(50, self.base_time)
        
        # Mock anomaly results (all normal)
        from cybersentinel_ai.ml.anomaly_detector import AnomalyResult
        anomalies = [
            AnomalyResult(
                event=e,
                raw_score=0.1,
                normalized_score=0.1,
                is_anomaly=False,
                feature_contributions={}
            )
            for e in events
        ]
        
        rule_matches = []
        attack_chains = []
        
        risk = self.engine.calculate_risk(events, anomalies, rule_matches, attack_chains)
        
        self.assertEqual(risk.severity.value, "LOW")
        self.assertLess(risk.total_score, 31)
    
    def test_coordinated_attack_critical_risk(self):
        events = self.generator.generate_coordinated_attack(self.base_time)
        
        # Mock high anomaly results
        from cybersentinel_ai.ml.anomaly_detector import AnomalyResult
        anomalies = [
            AnomalyResult(
                event=e,
                raw_score=-0.5,
                normalized_score=0.9,
                is_anomaly=True,
                feature_contributions={}
            )
            for e in events
        ]
        
        rule_matches = RuleEngine().evaluate(events)
        attack_chains = CorrelationEngine().correlate(events, rule_matches)
        
        risk = self.engine.calculate_risk(events, anomalies, rule_matches, attack_chains)
        
        self.assertIn(risk.severity.value, ["HIGH", "CRITICAL"])
        self.assertGreater(risk.total_score, 60)


class TestIncidentCreation(unittest.TestCase):
    """Tests for incident object creation."""
    
    def setUp(self):
        self.generator = LogGenerator(seed=42)
        self.base_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    def test_create_incident_from_coordinated_attack(self):
        events = self.generator.generate_coordinated_attack(self.base_time)
        
        # Run full analysis
        engine = CyberSentinelAI()
        
        # Train on normal first
        normal = self.generator.generate_normal_activity(200, self.base_time - timedelta(days=1))
        engine.train_anomaly_detector(normal)
        
        # Analyze attack
        result = engine.analyze_events(events)
        
        self.assertGreater(len(result["incidents"]), 0)
        
        incident = result["incidents"][0]
        self.assertIn("incident_id", incident)
        self.assertIn("severity", incident)
        self.assertIn("risk_score", incident)
        self.assertIn("attack_type", incident)
        self.assertIn("mitre_techniques", incident)
        self.assertIn("recommendations", incident)
        
        # Coordinated attack should be CRITICAL
        self.assertEqual(incident["severity"], "CRITICAL")
        self.assertGreater(incident["risk_score"], 80)
        self.assertGreater(len(incident["mitre_techniques"]), 0)
        self.assertGreater(len(incident["recommendations"]), 0)


class TestFullPipeline(unittest.TestCase):
    """Integration tests for the full analysis pipeline."""
    
    def setUp(self):
        self.generator = LogGenerator(seed=42)
        self.base_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    def test_all_scenarios(self):
        """Test that all attack scenarios produce appropriate results."""
        scenarios = {
            "normal_activity": "LOW",
            "brute_force": "MEDIUM",
            "account_compromise": "HIGH",
            "data_exfiltration": "HIGH",
            "coordinated_attack": "CRITICAL",
        }
        
        engine = CyberSentinelAI()
        
        # Train on normal activity
        normal = self.generator.generate_normal_activity(300, self.base_time - timedelta(days=1))
        engine.train_anomaly_detector(normal)
        
        for scenario, expected_min_severity in scenarios.items():
            with self.subTest(scenario=scenario):
                events = self.generator.generate_scenario(scenario, self.base_time)
                result = engine.analyze_events(events)
                
                if scenario == "normal_activity":
                    # Normal should have no incidents or LOW
                    if result["incidents"]:
                        self.assertEqual(result["incidents"][0]["severity"], "LOW")
                else:
                    # Attacks should produce incidents
                    self.assertGreater(len(result["incidents"]), 0)
                    
                    severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                    actual_severity = result["incidents"][0]["severity"]
                    self.assertGreaterEqual(
                        severity_order[actual_severity],
                        severity_order[expected_min_severity],
                        f"{scenario}: expected at least {expected_min_severity}, got {actual_severity}"
                    )
    
    def test_analyze_events_function(self):
        """Test the convenience analyze_events function."""
        events = self.generator.generate_brute_force(self.base_time)
        
        # Convert to dict format
        event_dicts = [e.to_dict() for e in events]
        
        result = analyze_events_from_dicts(event_dicts, train_on_events=True)
        
        self.assertIn("incidents", result)
        self.assertIn("anomalies", result)
        self.assertIn("attack_chains", result)
        self.assertIn("statistics", result)


class TestConfig(unittest.TestCase):
    """Tests for configuration."""
    
    def test_default_config(self):
        config = DEFAULT_CONFIG
        self.assertIsInstance(config.rules.brute_force_failed_attempts, int)
        self.assertEqual(config.rules.brute_force_failed_attempts, 5)
    
    def test_config_from_dict(self):
        data = {
            "rules": {"brute_force_failed_attempts": 10},
            "ml": {"contamination": 0.05},
        }
        config = Config.from_dict(data)
        self.assertEqual(config.rules.brute_force_failed_attempts, 10)
        self.assertEqual(config.ml.contamination, 0.05)
    
    def test_config_to_dict(self):
        config = DEFAULT_CONFIG
        data = config.to_dict()
        self.assertIn("rules", data)
        self.assertIn("ml", data)
        self.assertIn("correlation", data)
        self.assertIn("risk", data)


if __name__ == "__main__":
    unittest.main()
