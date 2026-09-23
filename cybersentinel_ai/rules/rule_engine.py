"""Deterministic rule engine for security event analysis."""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

from ..core.schemas import SecurityEvent, EventSource, EventType, Action
from ..core.config import Config, DEFAULT_CONFIG, RuleThresholds
from ..core.indicators import is_external_ip, is_sensitive_file


class RuleType(str, Enum):
    """Types of detection rules."""
    BRUTE_FORCE = "brute_force"
    ACCOUNT_COMPROMISE = "account_compromise"
    SUSPICIOUS_POWERSHELL = "suspicious_powershell"
    DATA_EXFILTRATION = "data_exfiltration"
    COORDINATED_ATTACK = "coordinated_attack"


class RuleSeverity(str, Enum):
    """Severity of rule match."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RuleMatch:
    """Result of a rule match."""
    rule_type: RuleType
    severity: RuleSeverity
    matched_events: List[SecurityEvent]
    evidence: Dict[str, Any]
    description: str
    confidence: float  # 0.0 to 1.0
    timestamp: datetime
    entities: Dict[str, Any] = field(default_factory=dict)  # user, ip, device, etc.


class RuleEngine:
    """Deterministic rule engine for detecting attack patterns."""
    
    def __init__(self, config=None):
        self.config = config or Config()
        self.thresholds: RuleThresholds = self.config.rules
    
    def evaluate(self, events: List[SecurityEvent]) -> List[RuleMatch]:
        """Evaluate all rules against events."""
        if not events:
            return []
        
        matches = []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Run each rule
        matches.extend(self._check_brute_force(sorted_events))
        matches.extend(self._check_account_compromise(sorted_events))
        matches.extend(self._check_suspicious_powershell(sorted_events))
        matches.extend(self._check_data_exfiltration(sorted_events))
        matches.extend(self._check_coordinated_attack(sorted_events))
        
        return matches
    
    def _check_brute_force(self, events):
        """Detect a burst preceding a success within the configured window."""
        matches, groups = [], defaultdict(list)
        for e in events:
            if e.source == EventSource.AUTHENTICATION and e.user and e.source_ip:
                groups[(e.source_ip, e.user)].append(e)
        window = timedelta(minutes=self.thresholds.brute_force_time_window_minutes)
        for (ip, user), group in groups.items():
            candidates = []
            for anchor in group:
                if self.thresholds.brute_force_require_success and anchor.event_type != EventType.SUCCESSFUL_LOGIN:
                    continue
                if anchor.event_type not in (EventType.FAILED_LOGIN, EventType.SUCCESSFUL_LOGIN):
                    continue
                failed = [e for e in group if e.event_type == EventType.FAILED_LOGIN
                          and anchor.timestamp - window <= e.timestamp <= anchor.timestamp]
                if len(failed) >= self.thresholds.brute_force_failed_attempts:
                    candidates.append((failed, anchor))
            if not candidates:
                continue
            failed, anchor = max(candidates, key=lambda c: (c[1].event_type == EventType.SUCCESSFUL_LOGIN, len(c[0])))
            success = anchor.event_type == EventType.SUCCESSFUL_LOGIN
            matches.append(RuleMatch(
                RuleType.BRUTE_FORCE, RuleSeverity.HIGH if success else RuleSeverity.MEDIUM,
                failed + ([anchor] if success else []),
                {"failed_count": len(failed), "successful_count": int(success),
                 "time_span_minutes": (anchor.timestamp - failed[0].timestamp).total_seconds() / 60,
                 "source_ip": ip, "target_user": user},
                f"Brute force: {len(failed)} failed logins for {user} from {ip}" +
                (" followed by successful login" if success else ""),
                0.9 if success else 0.7, failed[0].timestamp, {"source_ip": ip, "user": user}))
        return matches

    def _check_account_compromise(self, events):
        matches, groups = [], defaultdict(list)
        for e in events:
            if e.user and e.source == EventSource.AUTHENTICATION:
                groups[e.user].append(e)
        window = timedelta(hours=self.thresholds.account_compromise_time_window_hours)
        for user, group in groups.items():
            for login in group:
                if login.event_type != EventType.SUCCESSFUL_LOGIN:
                    continue
                known_ips = {e.source_ip for e in group if e.event_type == EventType.SUCCESSFUL_LOGIN
                             and login.timestamp - window <= e.timestamp < login.timestamp and e.source_ip}
                new_ip = bool(login.metadata.get("is_new_ip")) or bool(known_ips and login.source_ip and login.source_ip not in known_ips)
                unusual = bool(login.metadata.get("is_unusual_time")) or not 9 <= login.timestamp.hour < 17
                escalations = [e for e in group if e.event_type == EventType.PRIVILEGE_ESCALATION
                               and login.timestamp <= e.timestamp <= login.timestamp + window]
                required = [(self.thresholds.account_compromise_new_ip, new_ip),
                            (self.thresholds.account_compromise_unusual_time, unusual),
                            (self.thresholds.account_compromise_privilege_escalation, bool(escalations))]
                enabled = [present for flag, present in required if flag]
                if not enabled or not all(enabled):
                    continue
                indicators = sum([new_ip, unusual, bool(escalations)])
                ips = sorted(known_ips | ({login.source_ip} if login.source_ip else set()))
                matches.append(RuleMatch(
                    RuleType.ACCOUNT_COMPROMISE, RuleSeverity.CRITICAL if indicators == 3 else RuleSeverity.HIGH,
                    [login] + escalations,
                    {"unique_ips": ips, "new_ip_count": int(new_ip), "unusual_time_logins": int(unusual),
                     "privilege_escalations": len(escalations), "indicators_present": indicators, "user": user},
                    f"Account compromise indicators for {user}: {indicators}",
                    min(0.95, 0.6 + indicators * 0.1), login.timestamp, {"user": user, "source_ips": ips}))
                break
        return matches

    def _check_suspicious_powershell(self, events: List[SecurityEvent]) -> List[RuleMatch]:
        """Detect suspicious PowerShell: PowerShell execution + authentication anomaly or unusual device."""
        matches = []
        
        ps_events = [e for e in events if e.event_type == EventType.POWERSHELL_EXECUTION]
        auth_anomalies = [e for e in events 
                         if e.source == EventSource.AUTHENTICATION 
                         and e.event_type in [EventType.FAILED_LOGIN, EventType.PRIVILEGE_ESCALATION]]
        
        for ps_event in ps_events:
            # Check if command is suspicious
            cmd = str(ps_event.metadata.get("command", "")).lower()
            suspicious_keywords = [
                "invoke-expression", "iex", "downloadstring", "downloadfile",
                "bypass", "encodedcommand", "-enc", "disable", "exclusion",
                "add-mppreference", "set-mppreference", "new-localuser",
                "add-localgroupmember", "invoke-mimikatz", "mimikatz", "passwordneverexpires"
            ]
            is_suspicious = any(kw in cmd for kw in suspicious_keywords)
            
            if not is_suspicious:
                continue
            
            # Check for authentication anomaly (same user, recent time)
            has_auth_anomaly = False
            if ps_event.user:
                recent_auth = [
                    e for e in auth_anomalies
                    if e.user == ps_event.user
                    and 0 <= (ps_event.timestamp - e.timestamp).total_seconds() <= 3600  # 1 hour
                ]
                has_auth_anomaly = len(recent_auth) > 0
            
            has_unusual_device = bool(ps_event.metadata.get("is_unusual_device", False))
            enabled = []
            if self.thresholds.powershell_require_auth_anomaly:
                enabled.append(has_auth_anomaly)
            if self.thresholds.powershell_require_unusual_device:
                enabled.append(has_unusual_device)
            if enabled and not any(enabled):
                continue

            severity = RuleSeverity.HIGH if has_auth_anomaly else RuleSeverity.MEDIUM
            confidence = 0.85 if has_auth_anomaly else 0.65
            
            matches.append(RuleMatch(
                rule_type=RuleType.SUSPICIOUS_POWERSHELL,
                severity=severity,
                matched_events=[ps_event] + (recent_auth if has_auth_anomaly else []),
                evidence={
                    "command": ps_event.metadata.get("command", ""),
                    "is_suspicious": True,
                    "has_auth_anomaly": has_auth_anomaly,
                    "auth_anomaly_count": len(recent_auth) if has_auth_anomaly else 0,
                    "device": ps_event.device,
                    "user": ps_event.user,
                },
                description=f"Suspicious PowerShell execution by {ps_event.user} on {ps_event.device}: " +
                           f"{str(ps_event.metadata.get('command', ''))[:100]}",
                confidence=confidence,
                timestamp=ps_event.timestamp,
                entities={"user": ps_event.user, "device": ps_event.device},
            ))
        
        return matches
    
    def _check_data_exfiltration(self, events):
        matches = []
        window = timedelta(minutes=self.thresholds.exfiltration_time_window_minutes)
        for transfer in events:
            if transfer.event_type != EventType.DATA_TRANSFER or not transfer.user or not transfer.device:
                continue
            if transfer.metadata.get("bytes_sent", 0) <= self.thresholds.exfiltration_large_transfer_bytes:
                continue
            external = is_external_ip(transfer.destination_ip)
            if self.thresholds.exfiltration_unusual_destination and not external:
                continue
            accesses = [e for e in events if e.event_type == EventType.FILE_ACCESS
                        and e.user == transfer.user and e.device == transfer.device
                        and transfer.timestamp - window <= e.timestamp <= transfer.timestamp
                        and is_sensitive_file(e.metadata.get("file_path", ""))]
            if self.thresholds.exfiltration_sensitive_file_access and not accesses:
                continue
            matched = accesses + [transfer]
            matches.append(RuleMatch(
                RuleType.DATA_EXFILTRATION, RuleSeverity.CRITICAL if external else RuleSeverity.HIGH,
                matched, {"sensitive_files_accessed": len(accesses), "large_transfers": 1,
                          "total_bytes_sent": transfer.metadata.get("bytes_sent", 0),
                          "unusual_destinations": [transfer.destination_ip] if external else [],
                          "user": transfer.user, "device": transfer.device},
                f"Potential data exfiltration by {transfer.user} on {transfer.device}",
                0.9 if external else 0.7, matched[0].timestamp,
                {"user": transfer.user, "device": transfer.device}))
        return matches

    def _check_coordinated_attack(self, events):
        matches, groups, seen = [], defaultdict(list), set()
        for e in events:
            if e.user:
                groups[("user", e.user)].append(e)
            if e.device:
                groups[("device", e.device)].append(e)
        window = timedelta(minutes=self.thresholds.coordinated_time_window_minutes)
        for group in groups.values():
            sources = {e.source for e in group}
            if self.thresholds.coordinated_require_auth and not any(
                e.source == EventSource.AUTHENTICATION and e.event_type in
                (EventType.FAILED_LOGIN, EventType.PRIVILEGE_ESCALATION) for e in group
            ):
                continue
            if self.thresholds.coordinated_require_endpoint and EventSource.ENDPOINT not in sources:
                continue
            if self.thresholds.coordinated_require_network and not any(
                e.source in (EventSource.NETWORK, EventSource.FIREWALL)
                and e.metadata.get("bytes_sent", 0) > 10 * 1024 * 1024 for e in group
            ):
                continue
            for anchor in group:
                current = [e for e in group if anchor.timestamp <= e.timestamp <= anchor.timestamp + window]
                auth = [e for e in current if e.source == EventSource.AUTHENTICATION and e.event_type in
                        (EventType.FAILED_LOGIN, EventType.PRIVILEGE_ESCALATION)]
                endpoint = [e for e in current if e.source == EventSource.ENDPOINT and
                            (e.event_type in (EventType.SUSPICIOUS_PROCESS, EventType.PRIVILEGE_ESCALATION)
                             or (e.event_type == EventType.POWERSHELL_EXECUTION and
                                 any(k in str(e.metadata.get("command", "")).lower() for k in
                                     ("iex", "invoke-expression", "-enc", "downloadstring", "bypass", "mimikatz", "disable"))))]
                network = [e for e in current if e.source in (EventSource.NETWORK, EventSource.FIREWALL)
                           and e.metadata.get("bytes_sent", 0) > 10 * 1024 * 1024]
                required = [(self.thresholds.coordinated_require_auth, auth),
                            (self.thresholds.coordinated_require_endpoint, endpoint),
                            (self.thresholds.coordinated_require_network, network)]
                if not any(flag for flag, _ in required) or not all(items for flag, items in required if flag):
                    continue
                ids = frozenset(e.event_id for e in auth + endpoint + network)
                if ids in seen:
                    break
                seen.add(ids)
                entities = {"users": sorted({e.user for e in current if e.user}),
                            "devices": sorted({e.device for e in current if e.device}),
                            "source_ips": sorted({e.source_ip for e in current if e.source_ip})}
                matches.append(RuleMatch(
                    RuleType.COORDINATED_ATTACK, RuleSeverity.CRITICAL, current,
                    {"time_window_minutes": self.thresholds.coordinated_time_window_minutes,
                     "auth_anomalies": len(auth), "endpoint_anomalies": len(endpoint),
                     "network_anomalies": len(network), **entities},
                    "Related authentication, endpoint and network attack indicators",
                    0.95, anchor.timestamp, entities))
                break
        return matches

    _is_external_ip = staticmethod(is_external_ip)
