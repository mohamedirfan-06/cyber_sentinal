"""Common schemas and data structures for security events."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4
import math
import json
from typing import Any, Dict, List, Optional
from enum import Enum


class EventSource(str, Enum):
    """Source of the security event."""
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    FIREWALL = "firewall"
    ENDPOINT = "endpoint"
    APPLICATION = "application"


class EventType(str, Enum):
    """Type of security event."""
    # Authentication
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    
    # Network
    CONNECTION = "connection"
    PORT_SCAN = "port_scan"
    DATA_TRANSFER = "data_transfer"
    
    # Firewall
    BLOCKED_CONNECTION = "blocked_connection"
    ALLOWED_CONNECTION = "allowed_connection"
    RULE_VIOLATION = "rule_violation"
    
    # Endpoint
    PROCESS_EXECUTION = "process_execution"
    FILE_ACCESS = "file_access"
    REGISTRY_CHANGE = "registry_change"
    POWERSHELL_EXECUTION = "powershell_execution"
    SUSPICIOUS_PROCESS = "suspicious_process"
    
    # Application
    API_REQUEST = "api_request"
    AUTH_FAILURE = "auth_failure"
    UNUSUAL_ENDPOINT = "unusual_endpoint"


class Action(str, Enum):
    """Action taken."""
    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCESS = "login_success"
    LOGOUT = "logout"
    BLOCK = "block"
    ALLOW = "allow"
    EXECUTE = "execute"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    TRANSFER = "transfer"


@dataclass
class SecurityEvent:
    """Normalized security event schema."""
    timestamp: datetime
    source: EventSource
    event_type: EventType
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    device: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[Action] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_event: Optional[Dict[str, Any]] = None
    is_demo: bool = False
    event_id: str = field(default_factory=lambda: uuid4().hex)

    def __post_init__(self):
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        if not isinstance(self.timestamp, datetime):
            raise ValueError("timestamp must be a datetime or ISO8601 string")
        # Naive input timestamps are interpreted as UTC.
        self.timestamp = self.timestamp.replace(tzinfo=timezone.utc) if self.timestamp.tzinfo is None else self.timestamp.astimezone(timezone.utc)
        self.source = EventSource(self.source)
        self.event_type = EventType(self.event_type)
        if self.action is not None:
            self.action = Action(self.action)
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be an object")
        for name in ("user", "source_ip", "destination_ip", "device", "protocol"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be a string or null")
        if self.port is not None and (type(self.port) is not int or not 0 <= self.port <= 65535):
            raise ValueError("port must be an integer in [0, 65535] or null")
        if not isinstance(self.is_demo, bool):
            raise ValueError("is_demo must be a boolean")
        for name in ("process_name", "session_id", "endpoint", "command", "file_path"):
            value = self.metadata.get(name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"metadata.{name} must be a string or null")
        for name in ("is_new_ip", "is_unusual_time", "is_unusual_device", "is_suspicious"):
            if name in self.metadata and not isinstance(self.metadata[name], bool):
                raise ValueError(f"metadata.{name} must be a boolean")
        if self.raw_event is not None and not isinstance(self.raw_event, dict):
            raise ValueError("raw_event must be an object or null")
        try:
            json.dumps([self.metadata, self.raw_event], allow_nan=False)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("metadata and raw_event must contain finite JSON values") from exc
        if not isinstance(self.event_id, str) or not self.event_id:
            raise ValueError("event_id must be a non-empty string")
        for name in ("bytes_sent", "bytes_received"):
            value = self.metadata.get(name, 0)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise ValueError(f"metadata.{name} must be a finite non-negative number")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "source": self.source.value if isinstance(self.source, EventSource) else self.source,
            "event_type": self.event_type.value if isinstance(self.event_type, EventType) else self.event_type,
            "user": self.user,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "device": self.device,
            "port": self.port,
            "protocol": self.protocol,
            "action": self.action.value if isinstance(self.action, Action) else self.action,
            "metadata": self.metadata,
            "raw_event": self.raw_event,
            "is_demo": self.is_demo,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Create SecurityEvent from dictionary."""
        return cls(
            timestamp=data["timestamp"],
            source=EventSource(data["source"]) if isinstance(data["source"], str) else data["source"],
            event_type=EventType(data["event_type"]) if isinstance(data["event_type"], str) else data["event_type"],
            user=data.get("user"),
            source_ip=data.get("source_ip"),
            destination_ip=data.get("destination_ip"),
            device=data.get("device"),
            port=data.get("port"),
            protocol=data.get("protocol"),
            action=Action(data["action"]) if isinstance(data.get("action"), str) else data.get("action"),
            metadata=data.get("metadata", {}),
            raw_event=data.get("raw_event"),
            is_demo=data.get("is_demo", False),
            event_id=data.get("event_id", uuid4().hex),
        )


@dataclass
class FeatureVector:
    """Engineered features for ML model."""
    event: SecurityEvent
    features: Dict[str, float]
    feature_names: List[str]
    
    def to_array(self) -> List[float]:
        """Convert features to array in consistent order."""
        return [self.features.get(name, 0.0) for name in self.feature_names]
