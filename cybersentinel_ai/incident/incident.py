"""Incident object structure for detection results."""

from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum
import uuid

from ..core.schemas import SecurityEvent
from ..ml.anomaly_detector import AnomalyResult
from ..rules.rule_engine import RuleMatch
from ..correlation.correlation_engine import AttackChain
from ..graph.attack_graph import AttackGraph
from ..risk.risk_engine import RiskScore, SeverityLevel


class IncidentStatus(str, Enum):
    """Incident status."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"


@dataclass
class Incident:
    """Standard incident object for detected threats."""
    
    # Core identification
    incident_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # Classification
    severity: SeverityLevel = SeverityLevel.LOW
    risk_score: int = 0
    attack_type: str = "Unknown"
    status: IncidentStatus = IncidentStatus.OPEN
    
    # Timeline
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Entities involved
    users: List[str] = field(default_factory=list)
    devices: List[str] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    destination_ips: List[str] = field(default_factory=list)
    
    # Events and evidence
    events: List[SecurityEvent] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    
    # Analysis results
    anomaly_score: float = 0.0
    attack_chain: List[Dict[str, Any]] = field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Additional metadata
    rule_matches: List[str] = field(default_factory=list)  # Rule type names
    correlated_chains: List[str] = field(default_factory=list)  # Chain IDs
    graph_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Update timestamp on modification."""
        self.updated_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data["events"] = [event.to_dict() for event in self.events]
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        # Convert datetime objects to ISO format strings
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
            elif isinstance(value, list):
                data[key] = [
                    v.isoformat() if isinstance(v, datetime) else
                    v.to_dict() if hasattr(v, 'to_dict') else
                    v.value if hasattr(v, 'value') else v
                    for v in value
                ]
        return data
    
    def to_summary(self) -> Dict[str, Any]:
        """Get a summary view of the incident."""
        return {
            "incident_id": self.incident_id,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "attack_type": self.attack_type,
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "user_count": len(self.users),
            "device_count": len(self.devices),
            "event_count": len(self.events),
            "mitre_technique_count": len(self.mitre_techniques),
        }


class IncidentBuilder:
    """Builder for creating incidents from analysis results."""
    
    def __init__(self):
        self.incident = None
    
    def create_from_analysis(
        self,
        events: List[SecurityEvent],
        anomaly_results: List[AnomalyResult],
        rule_matches: List[RuleMatch],
        attack_chains: List[AttackChain],
        risk_score: RiskScore,
        attack_graph: Optional[AttackGraph] = None,
        mitre_techniques: Optional[List[Dict[str, str]]] = None,
    ) -> Incident:
        """Build incident from full analysis results."""
        
        # Determine primary attack type from rule matches or chains
        attack_type = self._determine_attack_type(rule_matches, attack_chains)
        
        # Extract entities
        users = list(set(e.user for e in events if e.user))
        devices = list(set(e.device for e in events if e.device))
        source_ips = list(set(e.source_ip for e in events if e.source_ip))
        destination_ips = list(set(e.destination_ip for e in events if e.destination_ip))
        
        # Timeline
        if events:
            start_time = min(e.timestamp for e in events)
            end_time = max(e.timestamp for e in events)
        else:
            start_time = end_time = None
        
        # Evidence from rule matches
        evidence = []
        for match in rule_matches:
            evidence.append({
                "type": "rule_match",
                "rule_type": match.rule_type.value,
                "severity": match.severity.value,
                "confidence": match.confidence,
                "description": match.description,
                "matched_event_count": len(match.matched_events),
                "entities": match.entities,
            })
        
        # Evidence from attack chains
        for chain in attack_chains:
            evidence.append({
                "type": "attack_chain",
                "chain_id": chain.chain_id,
                "attack_type": chain.attack_type,
                "correlation_score": chain.correlation_score,
                "event_count": len(chain.events),
                "description": chain.description,
                "entities": {k: list(v) for k, v in chain.entities.items()},
            })
        
        # Anomaly evidence
        if anomaly_results:
            max_anomaly = max(r.normalized_score for r in anomaly_results)
            anomaly_count = sum(1 for r in anomaly_results if r.is_anomaly)
            evidence.append({
                "type": "ml_anomaly",
                "max_anomaly_score": max_anomaly,
                "anomalous_event_count": anomaly_count,
                "total_events": len(anomaly_results),
            })
        
        # Build attack chain representation
        attack_chain_repr = []
        for chain in attack_chains:
            chain_steps = []
            for ce in chain.events:
                chain_steps.append({
                    "sequence": ce.sequence_number,
                    "timestamp": ce.event.timestamp.isoformat(),
                    "event_type": ce.event.event_type.value,
                    "source": ce.event.source.value,
                    "user": ce.event.user,
                    "device": ce.event.device,
                    "source_ip": ce.event.source_ip,
                    "destination_ip": ce.event.destination_ip,
                    "correlation_reasons": ce.correlation_reasons,
                })
            attack_chain_repr.append({
                "chain_id": chain.chain_id,
                "attack_type": chain.attack_type,
                "correlation_score": chain.correlation_score,
                "steps": chain_steps,
            })
        
        # Generate recommendations
        recommendations = self._generate_recommendations(rule_matches, attack_chains, risk_score)
        
        self.incident = Incident(
            severity=risk_score.severity,
            risk_score=risk_score.total_score,
            attack_type=attack_type,
            start_time=start_time,
            end_time=end_time,
            users=users,
            devices=devices,
            source_ips=source_ips,
            destination_ips=destination_ips,
            events=events,
            evidence=evidence,
            anomaly_score=max((r.normalized_score for r in anomaly_results), default=0.0),
            attack_chain=attack_chain_repr,
            mitre_techniques=mitre_techniques or [],
            recommendations=recommendations,
            rule_matches=[rm.rule_type.value for rm in rule_matches],
            correlated_chains=[c.chain_id for c in attack_chains],
            graph_id=attack_graph.graph_id if attack_graph else None,
            metadata={
                "risk_breakdown": {
                    "ml_component": risk_score.ml_component,
                    "rule_component": risk_score.rule_component,
                    "correlation_component": risk_score.correlation_component,
                    "cross_source_component": risk_score.cross_source_component,
                    "behavior_component": risk_score.behavior_component,
                },
                "analysis_details": risk_score.details,
            },
        )
        
        return self.incident
    
    def _determine_attack_type(
        self, 
        rule_matches: List[RuleMatch], 
        attack_chains: List[AttackChain]
    ) -> str:
        """Determine primary attack type."""
        if rule_matches:
            # Use highest severity rule match
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            top_rule = max(rule_matches, key=lambda rm: (severity_order.get(rm.severity.value, 0), rm.rule_type.value == "coordinated_attack", rm.confidence))
            type_map = {
                "brute_force": "Brute Force Attack",
                "account_compromise": "Account Compromise",
                "suspicious_powershell": "Suspicious PowerShell Activity",
                "data_exfiltration": "Data Exfiltration",
                "coordinated_attack": "Coordinated Attack",
            }
            return type_map.get(top_rule.rule_type.value, top_rule.rule_type.value.replace("_", " ").title())
        
        if attack_chains:
            # Use highest scoring chain
            top_chain = max(attack_chains, key=lambda c: c.correlation_score)
            chain_type_map = {
                "brute_force_to_compromise": "Brute Force to Compromise",
                "credential_theft_lateral": "Credential Theft & Lateral Movement",
                "malware_execution_exfil": "Malware Execution & Exfiltration",
            }
            return chain_type_map.get(top_chain.attack_type, top_chain.attack_type.replace("_", " ").title())
        
        return "Suspicious Activity"
    
    def _generate_recommendations(
        self,
        rule_matches: List[RuleMatch],
        attack_chains: List[AttackChain],
        risk_score: RiskScore,
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        rule_types = {rm.rule_type for rm in rule_matches}
        
        if any(rt in rule_types for rt in ["brute_force", "account_compromise"]):
            recommendations.extend([
                "Immediately reset credentials for affected user accounts",
                "Enable multi-factor authentication for all privileged accounts",
                "Block source IPs at firewall perimeter",
                "Review authentication logs for additional compromised accounts",
            ])
        
        if "suspicious_powershell" in rule_types:
            recommendations.extend([
                "Isolate affected endpoints from network",
                "Collect memory dumps and process artifacts for forensic analysis",
                "Review PowerShell script block logging for full command history",
                "Implement PowerShell Constrained Language Mode",
            ])
        
        if "data_exfiltration" in rule_types:
            recommendations.extend([
                "Block outbound connections to identified destination IPs",
                "Identify and classify exfiltrated data",
                "Notify data protection officer if PII/sensitive data involved",
                "Implement DLP controls for sensitive file access",
            ])
        
        if "coordinated_attack" in rule_types:
            recommendations.extend([
                "Activate incident response plan for coordinated attack",
                "Conduct full network sweep for lateral movement indicators",
                "Review all administrative account usage in last 72 hours",
                "Consider engaging external incident response team",
            ])
        
        # General recommendations based on severity
        if risk_score.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            recommendations.extend([
                "Escalate to SOC Tier 2/3 for immediate investigation",
                "Generate IOCs (IPs, hashes, domains) for threat intelligence sharing",
                "Initiate threat hunt for related activity across environment",
            ])
        elif risk_score.severity == SeverityLevel.MEDIUM:
            recommendations.extend([
                "Assign to SOC analyst for triage within 4 hours",
                "Enrich with threat intelligence feeds",
                "Monitor affected entities for escalation",
            ])
        else:
            recommendations.extend([
                "Log for trend analysis",
                "Review during next scheduled threat hunt",
            ])
        
        # Deduplicate
        return list(dict.fromkeys(recommendations))


def create_incident(
    events: List[SecurityEvent],
    anomaly_results: List[AnomalyResult],
    rule_matches: List[RuleMatch],
    attack_chains: List[AttackChain],
    risk_score: RiskScore,
    attack_graph: Optional[AttackGraph] = None,
    mitre_techniques: Optional[List[Dict[str, str]]] = None,
) -> Incident:
    """Convenience function to create incident."""
    builder = IncidentBuilder()
    return builder.create_from_analysis(
        events, anomaly_results, rule_matches, attack_chains,
        risk_score, attack_graph, mitre_techniques
    )
