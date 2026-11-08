import csv
import json
import math
from pathlib import Path
from typing import List, Dict, Any, Tuple
from app.ml.model import MLRiskEngine


def load_dataset(csv_path: str) -> List[Dict[str, Any]]:
    records = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append({
                "timestamp": row["timestamp"],
                "user_identifier": row["user_identifier"],
                "source_ip": row["source_ip"],
                "event_type": row["event_type"],
                "failed_attempts": int(row["failed_attempts"]),
                "hour_of_day": int(row["hour_of_day"]),
                "is_new_device": bool(int(row["is_new_device"])),
                "is_unusual_location": bool(int(row["is_unusual_location"])),
                "ip_reputation_score": float(row["ip_reputation_score"]),
                "threat_type": row["threat_type"],
                "is_malicious": int(row["is_malicious"])
            })
    return records


def evaluate_model(dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluates MLRiskEngine against labeled dataset.
    Calculates Confusion Matrix, Precision, Recall, F1-Score, and ROC-AUC proxy.
    """
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    threshold = 50.0  # Risk score >= 50 classified as Malicious

    for row in dataset:
        pred = MLRiskEngine.predict(
            failed_attempts=row["failed_attempts"],
            hour_of_day=row["hour_of_day"],
            is_new_device=row["is_new_device"],
            is_unusual_location=row["is_unusual_location"],
            ip_reputation_score=row["ip_reputation_score"],
            user_identifier=row["user_identifier"]
        )

        score = pred["risk_score"]
        predicted_malicious = 1 if score >= threshold else 0
        actual_malicious = row["is_malicious"]

        if predicted_malicious == 1 and actual_malicious == 1:
            tp += 1
        elif predicted_malicious == 1 and actual_malicious == 0:
            fp += 1
        elif predicted_malicious == 0 and actual_malicious == 0:
            tn += 1
        elif predicted_malicious == 0 and actual_malicious == 1:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(dataset) if dataset else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "dataset_size": len(dataset),
        "threshold": threshold,
        "confusion_matrix": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn
        },
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1_score": round(f1_score * 100, 2),
        "false_positive_rate": round(fpr * 100, 2),
        "model_version": MLRiskEngine.MODEL_VERSION
    }


def main():
    root = Path(__file__).resolve().parent.parent.parent.parent
    data_path = root / "data" / "auth_events_dataset.csv"
    if not data_path.exists():
        data_path = root / "backend" / "data" / "auth_events_dataset.csv"

    print(f"Loading dataset from: {data_path}")
    dataset = load_dataset(str(data_path))
    print(f"Loaded {len(dataset)} telemetry records.")

    print("\nEvaluating Machine Learning Risk Scoring Engine...")
    metrics = evaluate_model(dataset)

    print("\n================ MODEL EVALUATION REPORT ================")
    print(f"Accuracy:            {metrics['accuracy']}%")
    print(f"Precision:           {metrics['precision']}%")
    print(f"Recall:              {metrics['recall']}%")
    print(f"F1-Score:            {metrics['f1_score']}%")
    print(f"False Positive Rate: {metrics['false_positive_rate']}%")
    print("---------------------------------------------------------")
    print(f"True Positives:  {metrics['confusion_matrix']['true_positives']}")
    print(f"False Positives: {metrics['confusion_matrix']['false_positives']}")
    print(f"True Negatives:  {metrics['confusion_matrix']['true_negatives']}")
    print(f"False Negatives: {metrics['confusion_matrix']['false_negatives']}")
    print("=========================================================\n")

    metrics_out = Path(__file__).resolve().parent / "model_metrics.json"
    with open(metrics_out, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Saved evaluation metrics to: {metrics_out}")


if __name__ == "__main__":
    main()
