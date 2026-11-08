from typing import List, Optional
from pydantic import BaseModel, Field


class RiskPredictionRequest(BaseModel):
    failed_attempts: int = Field(default=0, ge=0)
    hour_of_day: int = Field(default=12, ge=0, le=23)
    is_new_device: bool = Field(default=False)
    is_unusual_location: bool = Field(default=False)
    ip_reputation_score: float = Field(default=0.0, ge=0.0, le=100.0, description="0=Clean, 100=Known malicious")
    user_identifier: Optional[str] = None


class RiskPredictionResponse(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Normalized risk score 0.0 - 100.0")
    risk_level: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(..., ge=0.0, le=1.0)
    prediction: str = Field(..., description="Classification: Benign, Suspicious, Malicious")
    contributing_factors: List[str]
    model_version: str = "v1.2-hybrid-ml"

