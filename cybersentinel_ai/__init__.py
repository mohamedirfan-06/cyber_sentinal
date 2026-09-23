"""CyberSentinel AI - AI/ML Security Event Analysis Module."""

from .api import CyberSentinelAI, analyze_events, analyze_events_from_dicts
from .core.schemas import SecurityEvent, EventSource, EventType, Action, FeatureVector
from .core.config import Config, DEFAULT_CONFIG
from .features import FeatureEngineer
from .ml import AnomalyDetector
from .rules import RuleEngine
from .correlation import CorrelationEngine
from .graph import AttackGraphBuilder
from .risk import RiskEngine
from .incident import Incident
from .generator import LogGenerator

__version__ = "1.0.0"
__all__ = [
    "analyze_events",
    "Incident",
    "LogGenerator",
    "CyberSentinelAI", "analyze_events_from_dicts", "SecurityEvent",
    "EventSource", "EventType", "Action", "FeatureVector", "Config",
    "DEFAULT_CONFIG", "FeatureEngineer", "AnomalyDetector", "RuleEngine",
    "CorrelationEngine", "AttackGraphBuilder", "RiskEngine",
]
