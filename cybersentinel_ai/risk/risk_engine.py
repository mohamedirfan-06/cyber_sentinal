"""Risk scoring engine for security incidents."""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from ..core.schemas import SecurityEvent
from ..core.config import Config, DEFAULT_CONFIG, RiskConfig
from ..ml.anomaly_detector import AnomalyResult
from ..rules.rule_engine import RuleMatch, RuleSeverity
from ..correlation.correlation_engine import AttackChain


class SeverityLevel(str, Enum):
    """Incident severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskScore:
    """Risk score breakdown."""
    total_score: int  # 0-100
    severity: SeverityLevel
    ml_component: float
    rule_component: float
    correlation_component: float
    cross_source_component: float
    behavior_component: float
    details: Dict[str, Any]


class RiskEngine:
    """Transparent risk scoring engine."""
    
    def __init__(self, config=None):
        self.config = config or Config()
        self.risk_config: RiskConfig = self.config.risk
        
        # Severity thresholds
        self.severity_thresholds = self.risk_config.severity_thresholds
    
    def calculate_risk(
        self,
        events: List[SecurityEvent],
        anomaly_results: List[AnomalyResult],
        rule_matches: List[RuleMatch],
        attack_chains: List[AttackChain],
    ) -> RiskScore:
        """Calculate comprehensive risk score."""
        
        # 1. ML Anomaly Component
        ml_score = self._calculate_ml_score(anomaly_results)
        
        # 2. Rule Match Component
        rule_score = self._calculate_rule_score(rule_matches)
        
        # 3. Correlation Component
        correlation_score = self._calculate_correlation_score(attack_chains)
        
        # 4. Cross-Source Evidence Component
        cross_source_score = self._calculate_cross_source_score(events)
        
        # 5. Suspicious Behavior Component
        behavior_score = self._calculate_behavior_score(events, rule_matches)
        
        # Weighted combination
        weights = self.risk_config
        total = (
            ml_score * weights.ml_weight +
            rule_score * weights.rule_weight +
            correlation_score * weights.correlation_weight +
            cross_source_score * weights.cross_source_weight +
            behavior_score * weights.suspicious_behavior_weight
        )
        
        # Scale to 0-100
        total_score = int(min(100, max(0, total * 100)))
        
        # Determine severity
        severity = self._determine_severity(total_score)
        
        return RiskScore(
            total_score=total_score,
            severity=severity,
            ml_component=ml_score * 100,
            rule_component=rule_score * 100,
            correlation_component=correlation_score * 100,
            cross_source_component=cross_source_score * 100,
            behavior_component=behavior_score * 100,
            details={
                "weights": {
                    "ml": weights.ml_weight,
                    "rule": weights.rule_weight,
                    "correlation": weights.correlation_weight,
                    "cross_source": weights.cross_source_weight,
                    "behavior": weights.suspicious_behavior_weight,
                },
                "anomaly_count": sum(1 for r in anomaly_results if r.is_anomaly),
                "rule_match_count": len(rule_matches),
                "chain_count": len(attack_chains),
                "max_chain_score": max((c.correlation_score for c in attack_chains), default=0),
                "source_diversity": len(set(e.source for e in events)),
            }
        )
    
    def _calculate_ml_score(self, anomaly_results: List[AnomalyResult]) -> float:
        """Calculate ML anomaly component (0-1)."""
        if not anomaly_results:
            return 0.0
        
        # Use max normalized anomaly score
        max_score = max(r.normalized_score for r in anomaly_results)
        anomaly_ratio = sum(1 for r in anomaly_results if r.is_anomaly) / len(anomaly_results)
        
        # Combine max score with ratio
        return (max_score * 0.7) + (anomaly_ratio * 0.3)
    
    def _calculate_rule_score(self, rule_matches: List[RuleMatch]) -> float:
        """Calculate rule match component (0-1)."""
        if not rule_matches:
            return 0.0
        
        # Weight by severity and confidence
        severity_weights = {
            RuleSeverity.LOW: 0.2,
            RuleSeverity.MEDIUM: 0.5,
            RuleSeverity.HIGH: 0.8,
            RuleSeverity.CRITICAL: 1.0,
        }
        
        total_weight = 0.0
        for match in rule_matches:
            weight = severity_weights.get(match.severity, 0.5)
            total_weight += weight * match.confidence
        
        # Normalize by max possible (assuming CRITICAL with confidence 1.0)
        max_possible = len(rule_matches) * 1.0
        return min(1.0, total_weight)
    
    def _calculate_correlation_score(self, attack_chains: List[AttackChain]) -> float:
        """Calculate correlation component (0-1)."""
        if not attack_chains:
            return 0.0
        
        # Use max chain correlation score
        max_chain_score = max(c.correlation_score for c in attack_chains)
        
        # Bonus for multiple chains
        chain_bonus = min(0.2, len(attack_chains) * 0.05)
        
        return min(1.0, max_chain_score + chain_bonus)
    
    def _calculate_cross_source_score(self, events: List[SecurityEvent]) -> float:
        """Calculate cross-source evidence component (0-1)."""
        if not events:
            return 0.0
        
        sources = set(e.source for e in events)
        source_count = len(sources)
        
        # More sources = higher score (max 5 sources)
        return min(1.0, source_count / 5.0)
    
    def _calculate_behavior_score(
        self, 
        events: List[SecurityEvent], 
        rule_matches: List[RuleMatch]
    ) -> float:
        """Calculate suspicious behavior component (0-1)."""
        if not events:
            return 0.0
        
        score = 0.0
        
        # Check for specific suspicious patterns
        auth_events = [e for e in events if e.source.value == "authentication"]
        endpoint_events = [e for e in events if e.source.value == "endpoint"]
        network_events = [e for e in events if e.source.value in ["network", "firewall"]]
        
        # Multiple failed logins
        failed_logins = [e for e in auth_events if e.event_type.value == "failed_login"]
        if len(failed_logins) > 10:
            score += 0.3
        elif len(failed_logins) > 5:
            score += 0.15
        
        # Privilege escalation
        priv_esc = [e for e in events if e.event_type.value == "privilege_escalation"]
        if priv_esc:
            score += 0.25
        
        # Suspicious PowerShell
        ps_events = [e for e in endpoint_events if e.event_type.value == "powershell_execution"]
        suspicious_ps = [e for e in ps_events if self._is_suspicious_powershell(e)]
        if suspicious_ps:
            score += 0.2
        
        # Large data transfer
        transfers = [e for e in network_events if e.event_type.value == "data_transfer"]
        large_transfers = [e for e in transfers if e.metadata.get("bytes_sent", 0) > 100 * 1024 * 1024]
        if large_transfers:
            score += 0.2
        
        # Sensitive file access
        file_access = [e for e in endpoint_events if e.event_type.value == "file_access"]
        sensitive_access = [
            e for e in file_access
            if any(s in str(e.metadata.get("file_path", "")).lower() 
                  for s in ["password", "secret", "key", "shadow", "salary", "payroll"])
        ]
        if sensitive_access:
            score += 0.15
        
        # New IP successful login
        new_ip_logins = [
            e for e in auth_events
            if e.event_type.value == "successful_login"
            and e.metadata.get("is_new_ip", False)
        ]
        if new_ip_logins:
            score += 0.15
        
        return min(1.0, score)
    
    def _is_suspicious_powershell(self, event: SecurityEvent) -> bool:
        """Check if PowerShell command is suspicious."""
        cmd = str(event.metadata.get("command", "")).lower()
        suspicious = [
            "invoke-expression", "iex", "downloadstring", "downloadfile",
            "bypass", "encodedcommand", "-enc", "disable", "exclusion",
            "add-mppreference", "set-mppreference", "new-localuser",
            "add-localgroupmember", "invoke-mimikatz", "mimikatz"
        ]
        return any(s in cmd for s in suspicious)
    
    def _determine_severity(self, score: int) -> SeverityLevel:
        """Determine severity from score."""
        if score > self.severity_thresholds.get("HIGH", 80):
            return SeverityLevel.CRITICAL
        elif score > self.severity_thresholds.get("MEDIUM", 60):
            return SeverityLevel.HIGH
        elif score > self.severity_thresholds.get("LOW", 30):
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW


def calculate_risk(
    events: List[SecurityEvent],
    anomaly_results: List[AnomalyResult],
    rule_matches: List[RuleMatch],
    attack_chains: List[AttackChain],
    config=None,
) -> RiskScore:
    """Convenience function to calculate risk."""
    engine = RiskEngine(config)
    return engine.calculate_risk(events, anomaly_results, rule_matches, attack_chains)
