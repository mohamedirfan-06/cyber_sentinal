"""ML-based anomaly detection using Isolation Forest."""

import numpy as np
import joblib
from typing import List, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ..core.config import Config, DEFAULT_CONFIG
from ..core.schemas import SecurityEvent
from ..features.feature_engineer import FeatureEngineer


@dataclass
class AnomalyResult:
    """Result of anomaly detection for a single event."""
    event: SecurityEvent
    raw_score: float
    normalized_score: float
    is_anomaly: bool
    feature_contributions: Dict[str, float]


class AnomalyDetector:
    """Isolation Forest-based anomaly detector for security events."""
    
    def __init__(self, config=None):
        self.config = config or Config()
        self.ml_config = self.config.ml
        
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_engineer = FeatureEngineer(self.config)
        self.is_trained = False
        self._feature_names = self.feature_engineer.get_feature_names()
    
    def train(self, events: List[SecurityEvent], reference_time: Optional[Any] = None) -> "AnomalyDetector":
        """Train the Isolation Forest model on normal events."""
        if not events:
            raise ValueError("Cannot train on empty event list")
        
        # Extract features
        X = self.feature_engineer.get_feature_matrix(events, reference_time)
        
        if len(X) == 0:
            raise ValueError("No features extracted from events")
        
        X = np.array(X, dtype=np.float32)
        
        # Handle any NaN or infinite values
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        # Fit scaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train Isolation Forest
        model = IsolationForest(
            contamination=self.ml_config.contamination,
            n_estimators=self.ml_config.n_estimators,
            max_samples=self.ml_config.max_samples,
            random_state=self.ml_config.random_state,
            n_jobs=-1,
        )
        model.fit(X_scaled)
        self.scaler = scaler
        self.model = model
        self.is_trained = True
        
        return self
    
    def predict(self, events: List[SecurityEvent], reference_time: Optional[Any] = None) -> List[AnomalyResult]:
        """Predict anomalies for events."""
        if not self.is_trained or self.model is None or self.scaler is None:
            raise RuntimeError("Model must be trained before prediction. Call train() first.")
        
        if not events:
            return []
        
        # Extract features
        X = self.feature_engineer.get_feature_matrix(events, reference_time)
        X = np.array(X, dtype=np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly scores (lower = more anomalous)
        raw_scores = self.model.decision_function(X_scaled)
        
        # Normalize scores to 0-1 range (higher = more anomalous)
        # Isolation Forest decision_function returns negative values for anomalies
        # We invert and normalize
        # A fixed transform preserves the fitted model's zero boundary and
        # works for single-event batches. These scores are not probabilities.
        normalized_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)
        
        # Determine anomalies based on threshold
        is_anomaly = normalized_scores > self.ml_config.anomaly_threshold
        
        # Calculate feature contributions (simplified: feature value * model feature importance)
        # For Isolation Forest, we approximate by looking at feature values relative to training data
        feature_contributions_list = self._compute_feature_contributions(X, X_scaled)
        
        results = []
        for i, event in enumerate(events):
            results.append(AnomalyResult(
                event=event,
                raw_score=float(raw_scores[i]),
                normalized_score=float(normalized_scores[i]),
                is_anomaly=bool(is_anomaly[i]),
                feature_contributions=feature_contributions_list[i],
            ))
        
        return results
    
    def _compute_feature_contributions(self, X: np.ndarray, X_scaled: np.ndarray) -> List[Dict[str, float]]:
        """Compute approximate feature contributions to anomaly score."""
        contributions_list = []
        
        for i in range(X.shape[0]):
            contributions = {}
            # For each feature, compute how far it deviates from mean (in scaled space)
            for j, name in enumerate(self._feature_names):
                if j < X_scaled.shape[1]:
                    # Scaled value indicates deviation from training distribution
                    contributions[name] = float(abs(X_scaled[i, j]))
            contributions_list.append(contributions)
        
        return contributions_list
    
    def predict_single(self, event: SecurityEvent, reference_time: Optional[Any] = None) -> AnomalyResult:
        """Predict anomaly for a single event."""
        results = self.predict([event], reference_time)
        return results[0] if results else None
    
    def save(self, model_path: str, scaler_path: Optional[str] = None) -> None:
        """Save trained model and scaler to disk."""
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained model")
        
        model_path = Path(model_path)
        scaler_path = Path(scaler_path) if scaler_path is not None else model_path.with_suffix('.scaler.pkl')
        if model_path.resolve() == scaler_path.resolve():
            raise ValueError("Model and scaler paths must be different")
        model_path.parent.mkdir(parents=True, exist_ok=True)
        
        joblib.dump({"model": self.model, "config": self.config.to_dict(),
                     "feature_names": self._feature_names}, model_path)
        
        if self.scaler:
            scaler_path = scaler_path or str(model_path.with_suffix('.scaler.pkl'))
            Path(scaler_path).parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.scaler, scaler_path)
    
    def load(self, model_path: str, scaler_path: Optional[str] = None) -> "AnomalyDetector":
        """Load trained model and scaler from disk."""
        model_path = Path(model_path)
        
        payload = joblib.load(model_path)
        model = payload["model"] if isinstance(payload, dict) else payload
        
        if scaler_path is None:
            scaler_path = model_path.with_suffix('.scaler.pkl')
        scaler = joblib.load(scaler_path)
        if not isinstance(model, IsolationForest) or not isinstance(scaler, StandardScaler):
            raise ValueError("Expected an IsolationForest model and StandardScaler")
        expected = len(self._feature_names)
        if getattr(model, "n_features_in_", None) != expected or getattr(scaler, "n_features_in_", None) != expected:
            raise ValueError("Saved model/scaler feature dimensions are incompatible")
        if isinstance(payload, dict):
            if payload["feature_names"] != self._feature_names:
                raise ValueError("Saved model feature schema is incompatible")
            from ..core.config import Config
            self.config = Config.from_dict(payload["config"])
            self.ml_config = self.config.ml
            self.feature_engineer = FeatureEngineer(self.config)
        self.model = model
        self.scaler = scaler
        
        self.is_trained = True
        return self
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        if not self.is_trained:
            return {"status": "not_trained"}
        
        return {
            "status": "trained",
            "model_type": "IsolationForest",
            "contamination": self.ml_config.contamination,
            "n_estimators": self.ml_config.n_estimators,
            "n_features": len(self._feature_names),
            "feature_names": self._feature_names,
            "anomaly_threshold": self.ml_config.anomaly_threshold,
        }


def create_detector(config=None) -> AnomalyDetector:
    """Factory function to create anomaly detector."""
    return AnomalyDetector(config)
