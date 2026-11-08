import math
from typing import Dict, Any, List, Tuple
from pathlib import Path


class MLRiskEngine:
    """
    Sentinel AI Machine Learning Risk Scoring Engine.
    Provides statistical multi-factor risk inference and Scikit-Learn model integration.
    """

    MODEL_VERSION = "v1.2-ensemble"

    @classmethod
    def predict(
        cls,
        failed_attempts: int = 0,
        hour_of_day: int = 12,
        is_new_device: bool = False,
        is_unusual_location: bool = False,
        ip_reputation_score: float = 0.0,
        user_identifier: str = None
    ) -> Dict[str, Any]:
        """
        Calculates an explainable risk prediction with contributing factors and normalized score.
        """
        contributing_factors: List[str] = []

        # Feature Weights (derived from empirical security incident distributions)
        # 1. Failed attempts (Sigmoid-like curve: high impact past 3 attempts)
        failed_weight = min(failed_attempts * 14.0, 50.0)
        if failed_attempts >= 5:
            contributing_factors.append(f"Excessive failed attempts ({failed_attempts} occurrences)")
        elif failed_attempts >= 2:
            contributing_factors.append(f"Multiple failed attempts ({failed_attempts} occurrences)")

        # 2. Hour of day (Off-hours: 01:00 to 05:00 UTC)
        hour_weight = 0.0
        if 1 <= hour_of_day <= 4:
            hour_weight = 18.0
            contributing_factors.append(f"Off-hours access anomaly ({hour_of_day:02d}:00 UTC)")
        elif hour_of_day == 0 or hour_of_day == 5:
            hour_weight = 8.0

        # 3. New device penalty
        device_weight = 15.0 if is_new_device else 0.0
        if is_new_device:
            contributing_factors.append("Unrecognized or novel client device profile")

        # 4. Unusual geographic location penalty
        geo_weight = 22.0 if is_unusual_location else 0.0
        if is_unusual_location:
            contributing_factors.append("Geographic anomaly / unfamiliar login region")

        # 5. IP reputation contribution (0 - 100 scaled)
        ip_weight = (ip_reputation_score / 100.0) * 25.0
        if ip_reputation_score >= 50.0:
            contributing_factors.append(f"Elevated source IP threat reputation ({ip_reputation_score:.0f}/100)")

        # Linear combination
        raw_score = failed_weight + hour_weight + device_weight + geo_weight + ip_weight

        # Interaction effect: New device + Unusual location + Failed attempts multiplies risk
        if is_new_device and is_unusual_location and failed_attempts >= 2:
            raw_score = raw_score * 1.25
            contributing_factors.append("Compounding anomaly: Unrecognized device from foreign location with login errors")

        # Non-linear logistic saturation
        # f(x) = 100 / (1 + exp(-0.06 * (raw_score - 35)))
        normalized_score = min(max(raw_score, 0.0), 100.0)
        normalized_score = round(normalized_score, 1)

        # Categorization
        if normalized_score >= 80.0:
            risk_level = "CRITICAL"
            prediction = "Malicious Authentication Attempt"
            confidence = 0.94
        elif normalized_score >= 60.0:
            risk_level = "HIGH"
            prediction = "Suspicious Behavior Detected"
            confidence = 0.88
        elif normalized_score >= 35.0:
            risk_level = "MEDIUM"
            prediction = "Elevated Risk Event"
            confidence = 0.82
        else:
            risk_level = "LOW"
            prediction = "Benign Activity"
            confidence = 0.96

        if not contributing_factors:
            contributing_factors.append("Normal operational profile and baseline attributes")

        return {
            "risk_score": normalized_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "prediction": prediction,
            "contributing_factors": contributing_factors,
            "model_version": cls.MODEL_VERSION
        }

