from app.ml.model import MLRiskEngine


def test_ml_benign_event_scoring():
    pred = MLRiskEngine.predict(
        failed_attempts=0,
        hour_of_day=14,
        is_new_device=False,
        is_unusual_location=False,
        ip_reputation_score=5.0
    )
    assert pred["risk_score"] < 35.0
    assert pred["risk_level"] == "LOW"
    assert pred["prediction"] == "Benign Activity"


def test_ml_high_risk_event_scoring():
    pred = MLRiskEngine.predict(
        failed_attempts=7,
        hour_of_day=2,
        is_new_device=True,
        is_unusual_location=True,
        ip_reputation_score=85.0
    )
    assert pred["risk_score"] >= 80.0
    assert pred["risk_level"] == "CRITICAL"
    assert "Excessive failed attempts" in str(pred["contributing_factors"])
    assert "Off-hours access anomaly" in str(pred["contributing_factors"])


def test_ml_boundary_conditions():
    # Extreme upper limit
    pred_max = MLRiskEngine.predict(failed_attempts=100, ip_reputation_score=100.0, is_new_device=True, is_unusual_location=True)
    assert pred_max["risk_score"] == 100.0

    # Extreme lower limit
    pred_min = MLRiskEngine.predict(failed_attempts=0, ip_reputation_score=0.0)
    assert pred_min["risk_score"] >= 0.0
