"""Main API interface for the CyberSentinel AI module."""

from typing import List, Dict, Any, Optional
from dataclasses import asdict

from ..core.schemas import SecurityEvent
from ..core.config import Config, DEFAULT_CONFIG
from ..generator.log_generator import LogGenerator
from ..features.feature_engineer import FeatureEngineer
from ..ml.anomaly_detector import AnomalyDetector, AnomalyResult
from ..rules.rule_engine import RuleEngine, RuleMatch
from ..correlation.correlation_engine import CorrelationEngine, AttackChain
from ..graph.attack_graph import AttackGraphBuilder, AttackGraph
from ..risk.risk_engine import RiskEngine, RiskScore
from ..incident.incident import Incident, create_incident
from ..mitre.mitre_mapper import map_to_mitre


class CyberSentinelAI:
    """Main entry point for the CyberSentinel AI analysis engine."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        
        # Initialize components
        self.generator = LogGenerator(self.config)
        self.feature_engineer = FeatureEngineer(self.config)
        self.anomaly_detector = AnomalyDetector(self.config)
        self.rule_engine = RuleEngine(self.config)
        self.correlation_engine = CorrelationEngine(self.config)
        self.graph_builder = AttackGraphBuilder()
        self.risk_engine = RiskEngine(self.config)
    
    def train_anomaly_detector(self, events: List[SecurityEvent]) -> "CyberSentinelAI":
        """Train the ML anomaly detector on baseline normal events."""
        self.anomaly_detector.train(events)
        return self
    
    def analyze_events(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Main analysis pipeline: analyze security events and return results.
        
        This is the primary function that Member 2 and Member 3 will call.
        
        Args:
            events: List of normalized SecurityEvent objects
            
        Returns:
            Dictionary containing:
            - incidents: List of detected incidents
            - anomalies: List of anomaly detection results
            - attack_chains: List of correlated attack chains
            - attack_graph: Attack graph representation
            - mitre_techniques: Mapped MITRE ATT&CK techniques
            - statistics: Analysis statistics
        """
        if not events:
            return self._empty_result()
        if len({event.event_id for event in events}) != len(events):
            raise ValueError("Each event in an analysis batch must have a unique event_id")
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        # Feature extraction and ML anomaly detection
        anomaly_results = []
        if self.anomaly_detector.is_trained:
            anomaly_results = self.anomaly_detector.predict(sorted_events)
        
        # 3. Rule Engine
        rule_matches = self.rule_engine.evaluate(sorted_events)
        
        # 4. Event Correlation
        attack_chains = self.correlation_engine.correlate(sorted_events, rule_matches)
        
        # 5. Attack Graph
        attack_graph = None
        if attack_chains:
            attack_graph = self.graph_builder.build_from_chains(attack_chains)
        
        # 6. Risk Scoring
        risk_score = self.risk_engine.calculate_risk(
            sorted_events, anomaly_results, rule_matches, attack_chains
        )
        
        # 7. MITRE ATT&CK Mapping
        evidence_ids = {event.event_id for match in rule_matches for event in match.matched_events}
        mitre_techniques = map_to_mitre(
            [event for event in sorted_events if event.event_id in evidence_ids], rule_matches, attack_chains
        )
        
        # 8. Incident Creation
        incidents = []
        if attack_chains or rule_matches:
            incident = create_incident(
                events=sorted_events,
                anomaly_results=anomaly_results,
                rule_matches=rule_matches,
                attack_chains=attack_chains,
                risk_score=risk_score,
                attack_graph=attack_graph,
                mitre_techniques=mitre_techniques,
            )
            incidents.append(incident)
        
        # Build response
        return {
            "incidents": [inc.to_dict() for inc in incidents],
            "anomalies": [self._anomaly_to_dict(a) for a in anomaly_results],
            "attack_chains": [self._chain_to_dict(c) for c in attack_chains],
            "attack_graph": attack_graph.to_dict() if attack_graph else None,
            "mitre_techniques": mitre_techniques,
            "statistics": self._compute_statistics(
                sorted_events, anomaly_results, rule_matches, attack_chains, risk_score
            ),
        }
    
    def analyze_events_simple(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze events from dictionary format (for API integration)."""
        security_events = [SecurityEvent.from_dict(e) for e in events]
        return self.analyze_events(security_events)
    
    def _anomaly_to_dict(self, anomaly: AnomalyResult) -> Dict[str, Any]:
        """Convert anomaly result to dictionary."""
        return {
            "event_id": anomaly.event.event_id,
            "raw_score": anomaly.raw_score,
            "normalized_score": anomaly.normalized_score,
            "is_anomaly": anomaly.is_anomaly,
            "top_contributing_features": dict(
                sorted(anomaly.feature_contributions.items(), 
                      key=lambda x: x[1], reverse=True)[:5]
            ),
        }
    
    def _chain_to_dict(self, chain: AttackChain) -> Dict[str, Any]:
        """Convert attack chain to dictionary."""
        return {
            "chain_id": chain.chain_id,
            "attack_type": chain.attack_type,
            "correlation_score": chain.correlation_score,
            "start_time": chain.start_time.isoformat(),
            "end_time": chain.end_time.isoformat(),
            "event_count": len(chain.events),
            "entities": {k: list(v) for k, v in chain.entities.items()},
            "description": chain.description,
            "steps": [
                {
                    "sequence": ce.sequence_number,
                    "timestamp": ce.event.timestamp.isoformat(),
                    "event_type": ce.event.event_type.value,
                    "source": ce.event.source.value,
                    "user": ce.event.user,
                    "device": ce.event.device,
                    "source_ip": ce.event.source_ip,
                    "destination_ip": ce.event.destination_ip,
                    "correlation_reasons": ce.correlation_reasons,
                }
                for ce in chain.events
            ],
        }
    
    def _compute_statistics(
        self,
        events: List[SecurityEvent],
        anomalies: List[AnomalyResult],
        rule_matches: List[RuleMatch],
        attack_chains: List[AttackChain],
        risk_score: RiskScore,
    ) -> Dict[str, Any]:
        """Compute analysis statistics."""
        return {
            "total_events": len(events),
            "event_sources": {
                source.value: sum(1 for e in events if e.source == source)
                for source in set(e.source for e in events)
            },
            "event_types": {
                et.value: sum(1 for e in events if e.event_type == et)
                for et in set(e.event_type for e in events)
            },
            "unique_users": len(set(e.user for e in events if e.user)),
            "unique_devices": len(set(e.device for e in events if e.device)),
            "unique_source_ips": len(set(e.source_ip for e in events if e.source_ip)),
            "anomaly_count": sum(1 for a in anomalies if a.is_anomaly),
            "anomaly_rate": sum(1 for a in anomalies if a.is_anomaly) / max(1, len(anomalies)),
            "rule_match_count": len(rule_matches),
            "rule_matches_by_type": {
                rt.value: sum(1 for rm in rule_matches if rm.rule_type == rt)
                for rt in set(rm.rule_type for rm in rule_matches)
            },
            "attack_chain_count": len(attack_chains),
            "max_chain_score": max((c.correlation_score for c in attack_chains), default=0),
            "risk_score": risk_score.total_score,
            "severity": risk_score.severity.value,
            "ml_trained": self.anomaly_detector.is_trained,
        }
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure."""
        return {
            "incidents": [],
            "anomalies": [],
            "attack_chains": [],
            "attack_graph": None,
            "mitre_techniques": [],
            "statistics": {
                "total_events": 0,
                "event_sources": {},
                "event_types": {},
                "unique_users": 0,
                "unique_devices": 0,
                "unique_source_ips": 0,
                "anomaly_count": 0,
                "anomaly_rate": 0.0,
                "rule_match_count": 0,
                "rule_matches_by_type": {},
                "attack_chain_count": 0,
                "max_chain_score": 0.0,
                "risk_score": 0,
                "severity": "LOW",
                "ml_trained": self.anomaly_detector.is_trained,
            },
        }


# Convenience function for direct use
def analyze_events(
    events: List[SecurityEvent],
    config: Optional[Config] = None,
    train_on_events: bool = False,
) -> Dict[str, Any]:
    """Convenience function to analyze events directly.
    
    Args:
        events: List of SecurityEvent objects
        config: Optional configuration
        train_on_events: If True, train anomaly detector on these events first
        
    Returns:
        Analysis results dictionary
    """
    engine = CyberSentinelAI(config)
    
    if train_on_events and events:
        engine.train_anomaly_detector(events)
    
    return engine.analyze_events(events)


def analyze_events_from_dicts(
    events: List[Dict[str, Any]],
    config: Optional[Config] = None,
    train_on_events: bool = False,
) -> Dict[str, Any]:
    """Analyze events from dictionary format."""
    security_events = [SecurityEvent.from_dict(e) for e in events]
    return analyze_events(security_events, config, train_on_events)
