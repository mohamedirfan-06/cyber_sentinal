"""Configuration management for the AI module."""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional
import math
from copy import deepcopy


@dataclass
class RuleThresholds:
    """Configurable thresholds for rule engine."""
    # Brute force
    brute_force_failed_attempts: int = 5
    brute_force_time_window_minutes: int = 15
    brute_force_require_success: bool = True
    
    # Account compromise
    account_compromise_new_ip: bool = True
    account_compromise_unusual_time: bool = True
    account_compromise_privilege_escalation: bool = True
    account_compromise_time_window_hours: int = 24
    
    # Suspicious PowerShell
    powershell_require_auth_anomaly: bool = True
    powershell_require_unusual_device: bool = False
    
    # Data exfiltration
    exfiltration_sensitive_file_access: bool = True
    exfiltration_large_transfer_bytes: int = 100 * 1024 * 1024  # 100 MB
    exfiltration_unusual_destination: bool = True
    exfiltration_time_window_minutes: int = 60
    
    # Coordinated attack
    coordinated_require_auth: bool = True
    coordinated_require_endpoint: bool = True
    coordinated_require_network: bool = True
    coordinated_time_window_minutes: int = 30


@dataclass
class MLConfig:
    """Configuration for ML model."""
    contamination: float = 0.1
    n_estimators: int = 100
    max_samples: str = "auto"
    random_state: int = 42
    anomaly_threshold: float = 0.5
    feature_window_minutes: int = 60


@dataclass
class CorrelationConfig:
    """Configuration for event correlation."""
    time_window_minutes: int = 30
    max_chain_length: int = 20
    min_chain_score: float = 0.3
    correlation_keys: list = field(default_factory=lambda: [
        "source_ip", "destination_ip", "user", "device", "process", "session_id"
    ])


@dataclass
class RiskConfig:
    """Configuration for risk scoring."""
    ml_weight: float = 0.3
    rule_weight: float = 0.3
    correlation_weight: float = 0.2
    cross_source_weight: float = 0.1
    suspicious_behavior_weight: float = 0.1
    
    severity_thresholds: Dict[str, int] = field(default_factory=lambda: {
        "LOW": 30,
        "MEDIUM": 60,
        "HIGH": 80,
        "CRITICAL": 100,
    })


@dataclass
class Config:
    """Main configuration class."""
    rules: RuleThresholds = field(default_factory=RuleThresholds)
    ml: MLConfig = field(default_factory=MLConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)

    def __post_init__(self):
        # Validate types before comparisons, slicing, or third-party model calls.
        for section_name in ("rules", "ml", "correlation", "risk"):
            section = getattr(self, section_name)
            defaults = type(section)()
            for name, value in asdict(section).items():
                default = getattr(defaults, name)
                if isinstance(default, bool):
                    if not isinstance(value, bool):
                        raise ValueError(f"{section_name}.{name} must be a boolean")
                elif isinstance(default, (int, float)):
                    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                        raise ValueError(f"{section_name}.{name} must be a finite number")
        for name, value in (("n_estimators", self.ml.n_estimators),
                            ("random_state", self.ml.random_state),
                            ("max_chain_length", self.correlation.max_chain_length),
                            ("brute_force_failed_attempts", self.rules.brute_force_failed_attempts)):
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{name} must be an integer")
        if not 0 <= self.ml.random_state < 2**32:
            raise ValueError("ml.random_state must be in [0, 2**32)")
        samples = self.ml.max_samples
        if not (samples == "auto" or
                (type(samples) is int and samples >= 1) or
                (type(samples) is float and math.isfinite(samples) and 0 < samples <= 1)):
            raise ValueError("ml.max_samples must be 'auto', a positive integer, or a fraction in (0, 1]")
        keys = self.correlation.correlation_keys
        allowed = {"source_ip", "destination_ip", "user", "device", "process", "session_id"}
        if not isinstance(keys, list) or any(not isinstance(k, str) or k not in allowed for k in keys):
            raise ValueError("correlation_keys must be a list of supported entity names")
        if not 0 < self.ml.contamination <= 0.5:
            raise ValueError("ml.contamination must be in (0, 0.5]")
        if not 0 <= self.ml.anomaly_threshold <= 1:
            raise ValueError("ml.anomaly_threshold must be in [0, 1]")
        if self.ml.n_estimators < 1 or self.ml.feature_window_minutes <= 0:
            raise ValueError("ML estimator count and feature window must be positive")
        if self.correlation.max_chain_length < 2 or self.correlation.time_window_minutes <= 0:
            raise ValueError("Correlation requires a positive window and chain length >= 2")
        if not 0 <= self.correlation.min_chain_score <= 1:
            raise ValueError("correlation.min_chain_score must be in [0, 1]")
        for name, value in asdict(self.rules).items():
            if not isinstance(value, bool) and value <= 0:
                raise ValueError(f"rules.{name} must be positive")
        weights = [self.risk.ml_weight, self.risk.rule_weight, self.risk.correlation_weight,
                   self.risk.cross_source_weight, self.risk.suspicious_behavior_weight]
        if any(w < 0 for w in weights) or sum(weights) <= 0:
            raise ValueError("Risk weights must be non-negative with a positive total")
        limits = self.risk.severity_thresholds
        if not isinstance(limits, dict) or any(type(v) is not int for v in limits.values()):
            raise ValueError("Severity thresholds must be integer upper bounds")
        if set(limits) != {"LOW", "MEDIUM", "HIGH", "CRITICAL"} or not (
            0 <= limits["LOW"] < limits["MEDIUM"] < limits["HIGH"] < limits["CRITICAL"] == 100
        ):
            raise ValueError("Severity thresholds must be ascending upper bounds ending at 100")
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create config from dictionary."""
        if not isinstance(data, dict) or set(data) - {"rules", "ml", "correlation", "risk"}:
            raise ValueError("Config must contain only rules, ml, correlation, and risk sections")
        if any(not isinstance(v, dict) for v in data.values()):
            raise ValueError("Config sections must be objects")
        data = deepcopy(data)
        return cls(
            rules=RuleThresholds(**data.get("rules", {})),
            ml=MLConfig(**data.get("ml", {})),
            correlation=CorrelationConfig(**data.get("correlation", {})),
            risk=RiskConfig(**data.get("risk", {})),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return asdict(self)


DEFAULT_CONFIG = Config()
