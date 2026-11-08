from fastapi import APIRouter, Depends
from app.schemas.ml import RiskPredictionRequest, RiskPredictionResponse
from app.ml.model import MLRiskEngine
from app.models.user import User
from app.api.deps import get_current_user

router = APIRouter(prefix="/ml", tags=["Machine Learning Risk Engine"])


@router.post("/predict-risk", response_model=RiskPredictionResponse)
def predict_event_risk(
    request_in: RiskPredictionRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Evaluates authentication and telemetry features through the Sentinel AI Machine Learning Risk Engine.
    Returns normalized 0–100 risk score, classification, confidence, and primary contributing factors.
    """
    prediction = MLRiskEngine.predict(
        failed_attempts=request_in.failed_attempts,
        hour_of_day=request_in.hour_of_day,
        is_new_device=request_in.is_new_device,
        is_unusual_location=request_in.is_unusual_location,
        ip_reputation_score=request_in.ip_reputation_score,
        user_identifier=request_in.user_identifier
    )
    return prediction


@router.get("/model-info")
def get_model_information(current_user: User = Depends(get_current_user)):
    """Returns technical metadata about the active ML risk assessment model."""
    return {
        "model_version": MLRiskEngine.MODEL_VERSION,
        "algorithm": "Gradient-Boosted Ensemble Risk Classifier with Multi-factor Saturation",
        "supported_features": [
            "failed_attempts",
            "hour_of_day",
            "is_new_device",
            "is_unusual_location",
            "ip_reputation_score"
        ],
        "output_range": "0.0 - 100.0",
        "thresholds": {
            "CRITICAL": ">= 80.0",
            "HIGH": "60.0 - 79.9",
            "MEDIUM": "35.0 - 59.9",
            "LOW": "< 35.0"
        }
    }
