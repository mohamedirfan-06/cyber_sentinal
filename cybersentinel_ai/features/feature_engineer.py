"""Feature engineering for security events."""

from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter
from bisect import bisect_left, bisect_right
import math

from ..core.indicators import is_external_ip
from ..core.schemas import SecurityEvent, EventSource, EventType, Action, FeatureVector
from ..core.config import Config, DEFAULT_CONFIG


class FeatureEngineer:
    """Extract behavioral features from security events for ML model."""
    
    # Standard feature names in consistent order
    FEATURE_NAMES = [
        # Authentication features
        "failed_login_count",
        "successful_login_count",
        "login_frequency_per_min",
        "unusual_login_time_score",
        "new_source_ip_count",
        "privilege_change_count",
        "unique_users_per_ip",
        "unique_ips_per_user",
        
        # Network features
        "connections_per_minute",
        "unique_destination_count",
        "bytes_sent_total",
        "bytes_received_total",
        "bytes_sent_per_connection",
        "unusual_port_score",
        "external_connection_ratio",
        
        # Endpoint features
        "suspicious_process_count",
        "powershell_execution_count",
        "endpoint_privilege_change_count",
        "unique_processes_executed",
        "file_access_count",
        "sensitive_file_access_count",
        
        # Application features
        "request_frequency_per_min",
        "auth_failure_count",
        "unusual_endpoint_count",
        "unique_endpoints_accessed",
        
        # Cross-source features
        "source_diversity_score",
        "event_type_diversity",
        "time_span_minutes",
    ]
    
    # Known suspicious ports
    SUSPICIOUS_PORTS = {22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9001}
    
    # Common business hours (9-17)
    BUSINESS_HOURS_START = 9
    BUSINESS_HOURS_END = 17
    
    def __init__(self, config=None):
        self.config = config or Config()
        self.window_minutes = self.config.ml.feature_window_minutes
    
    def extract_features(self, events: List[SecurityEvent], reference_time: Optional[datetime] = None) -> List[FeatureVector]:
        """Extract feature vectors for each event based on sliding window."""
        if not events:
            return []
        
        if reference_time is not None and reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)
        ordered = sorted(events, key=lambda e: e.timestamp)
        timestamps = [e.timestamp for e in ordered]
        feature_vectors = []
        for event in events:
            cutoff = min(event.timestamp, reference_time) if reference_time else event.timestamp
            window_start = cutoff - timedelta(minutes=self.window_minutes)
            window_events = ordered[bisect_left(timestamps, window_start):bisect_right(timestamps, cutoff)]
            ip_events, user_events, device_events = defaultdict(list), defaultdict(list), defaultdict(list)
            for e in window_events:
                if e.source_ip:
                    ip_events[e.source_ip].append(e)
                if e.user:
                    user_events[e.user].append(e)
                if e.device:
                    device_events[e.device].append(e)
            features = self._compute_event_features(
                event, window_events, ip_events, user_events, device_events, cutoff
            )
            feature_vectors.append(FeatureVector(
                event=event,
                features=features,
                feature_names=self.FEATURE_NAMES.copy()
            ))
        
        return feature_vectors
    
    def _compute_event_features(
        self,
        event: SecurityEvent,
        window_events: List[SecurityEvent],
        ip_events: Dict[str, List[SecurityEvent]],
        user_events: Dict[str, List[SecurityEvent]],
        device_events: Dict[str, List[SecurityEvent]],
        reference_time: datetime
    ) -> Dict[str, float]:
        """Compute all features for a single event."""
        features = {}
        
        # Time window in minutes
        window_span = max(1, (reference_time - min((e.timestamp for e in window_events), default=reference_time)).total_seconds() / 60)
        
        # --- Authentication Features ---
        auth_events = [e for e in window_events if e.source == EventSource.AUTHENTICATION]
        
        features["failed_login_count"] = sum(
            1 for e in auth_events if e.event_type == EventType.FAILED_LOGIN
        )
        features["successful_login_count"] = sum(
            1 for e in auth_events if e.event_type == EventType.SUCCESSFUL_LOGIN
        )
        features["login_frequency_per_min"] = len(auth_events) / window_span
        
        # Unusual login time (outside business hours)
        unusual_logins = sum(
            1 for e in auth_events
            if e.event_type == EventType.SUCCESSFUL_LOGIN
            and not (self.BUSINESS_HOURS_START <= e.timestamp.hour < self.BUSINESS_HOURS_END)
        )
        features["unusual_login_time_score"] = unusual_logins / max(1, features["successful_login_count"])
        
        # New source IPs
        if event.source_ip:
            features["new_source_ip_count"] = len(set(
                e.source_ip for e in auth_events
                if e.event_type == EventType.SUCCESSFUL_LOGIN and e.source_ip
            ))
        else:
            features["new_source_ip_count"] = 0
        
        features["privilege_change_count"] = sum(
            1 for e in auth_events if e.event_type == EventType.PRIVILEGE_ESCALATION
        )
        
        # Unique users per IP / unique IPs per user
        if event.source_ip:
            features["unique_users_per_ip"] = len(set(
                e.user for e in ip_events.get(event.source_ip, []) if e.user
            ))
        else:
            features["unique_users_per_ip"] = 0
        
        if event.user:
            features["unique_ips_per_user"] = len(set(
                e.source_ip for e in user_events.get(event.user, []) if e.source_ip
            ))
        else:
            features["unique_ips_per_user"] = 0
        
        # --- Network Features ---
        net_events = [e for e in window_events if e.source in [EventSource.NETWORK, EventSource.FIREWALL]]
        
        features["connections_per_minute"] = len(net_events) / window_span
        
        if event.source_ip:
            features["unique_destination_count"] = len(set(
                e.destination_ip for e in net_events
                if e.source_ip == event.source_ip and e.destination_ip
            ))
        else:
            features["unique_destination_count"] = 0
        
        features["bytes_sent_total"] = sum(
            e.metadata.get("bytes_sent", 0) for e in net_events
        )
        features["bytes_received_total"] = sum(
            e.metadata.get("bytes_received", 0) for e in net_events
        )
        features["bytes_sent_per_connection"] = (
            features["bytes_sent_total"] / max(1, len(net_events))
        )
        
        # Unusual port score
        unusual_ports = sum(
            1 for e in net_events
            if e.port and e.port in self.SUSPICIOUS_PORTS
        )
        features["unusual_port_score"] = unusual_ports / max(1, len(net_events))
        
        # External connection ratio
        external_conns = sum(
            1 for e in net_events
            if e.destination_ip and self._is_external_ip(e.destination_ip)
        )
        features["external_connection_ratio"] = external_conns / max(1, len(net_events))
        
        # --- Endpoint Features ---
        ep_events = [e for e in window_events if e.source == EventSource.ENDPOINT]
        
        features["suspicious_process_count"] = sum(
            1 for e in ep_events if e.event_type == EventType.SUSPICIOUS_PROCESS
        )
        features["powershell_execution_count"] = sum(
            1 for e in ep_events if e.event_type == EventType.POWERSHELL_EXECUTION
        )
        features["endpoint_privilege_change_count"] = sum(
            1 for e in ep_events if e.event_type == EventType.PRIVILEGE_ESCALATION
        )
        
        if event.device:
            features["unique_processes_executed"] = len(set(
                e.metadata.get("process_name") for e in device_events.get(event.device, [])
                if e.event_type == EventType.PROCESS_EXECUTION and e.metadata.get("process_name")
            ))
        else:
            features["unique_processes_executed"] = 0
        
        features["file_access_count"] = sum(
            1 for e in ep_events if e.event_type == EventType.FILE_ACCESS
        )
        
        # Sensitive file access
        sensitive_paths = [
            "password", "secret", "key", "shadow", "id_rsa", "config",
            "salary", "payroll", "customer", "finance", "hr"
        ]
        features["sensitive_file_access_count"] = sum(
            1 for e in ep_events
            if e.event_type == EventType.FILE_ACCESS
            and any(s in str(e.metadata.get("file_path", "")).lower() for s in sensitive_paths)
        )
        
        # --- Application Features ---
        app_events = [e for e in window_events if e.source == EventSource.APPLICATION]
        
        features["request_frequency_per_min"] = len(app_events) / window_span
        features["auth_failure_count"] = sum(
            1 for e in app_events if e.event_type == EventType.AUTH_FAILURE
        )
        
        if event.user:
            features["unusual_endpoint_count"] = sum(
                1 for e in app_events
                if e.user == event.user and e.event_type == EventType.UNUSUAL_ENDPOINT
            )
        else:
            features["unusual_endpoint_count"] = 0
        
        features["unique_endpoints_accessed"] = len(set(
            e.metadata.get("endpoint") for e in app_events
            if e.metadata.get("endpoint")
        ))
        
        # --- Cross-Source Features ---
        source_types = set(e.source for e in window_events)
        features["source_diversity_score"] = len(source_types) / len(EventSource)
        
        event_types = set(e.event_type for e in window_events)
        features["event_type_diversity"] = len(event_types) / len(EventType)
        
        if window_events:
            time_span = (max(e.timestamp for e in window_events) - min(e.timestamp for e in window_events)).total_seconds() / 60
            features["time_span_minutes"] = time_span
        else:
            features["time_span_minutes"] = 0
        
        return features
    
    _is_external_ip = staticmethod(is_external_ip)

    def get_feature_matrix(self, events: List[SecurityEvent], reference_time: Optional[datetime] = None) -> List[List[float]]:
        """Get feature matrix for ML model (list of feature arrays)."""
        vectors = self.extract_features(events, reference_time)
        return [v.to_array() for v in vectors]
    
    def get_feature_names(self) -> List[str]:
        """Get ordered feature names."""
        return self.FEATURE_NAMES.copy()
