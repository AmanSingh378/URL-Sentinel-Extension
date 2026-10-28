"""Train and evaluate the URL Sentinel Random Forest baseline."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.ml.features import FEATURE_NAMES, extract_url_features

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "backend" / "models" / "url_model.joblib"
METRICS_PATH = ROOT / "ml" / "evaluation_results.json"

LABEL_MAP = {
    "0": 0, "legitimate": 0, "benign": 0, "safe": 0,
    "1": 1, "phishing": 1, "malicious": 1, "fake": 1, "unsafe": 1,
}


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            "Provide a CSV file with columns named url and label."
        )

    df = pd.read_csv(path)

    required = {"url", "label"}
    if not required.issubset(df.columns):
        raise ValueError("CSV must contain both 'url' and 'label' columns.")

    df = df[["url", "label"]].dropna().copy()
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df["label"] = df["label"].map(LABEL_MAP)
    df = df.dropna()
    df["label"] = df["label"].astype(int)
    df = df[df["url"].str.len().between(8, 2048)]
    df = df.drop_duplicates(subset=["url"])

    if set(df["label"].unique()) != {0, 1}:
        raise ValueError(
            "Dataset must contain both classes: legitimate (0) and phishing (1)."
        )

    counts = df["label"].value_counts()
    if counts.min() < 4:
        raise ValueError(
            "At least 4 unique examples per class are required for this baseline. "
            "Use a larger, representative dataset for meaningful evaluation."
        )

    return df


def make_features(urls: pd.Series) -> pd.DataFrame:
    return pd.DataFrame(
        [extract_url_features(url) for url in urls],
        columns=FEATURE_NAMES,
    )


def create_model() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data",
        required=True,
        help="Path to a labeled CSV with url,label columns.",
    )
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.is_absolute():
        data_path = ROOT / data_path

    df = load_dataset(data_path)
    X = make_features(df["url"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    evaluation_model = create_model()
    evaluation_model.fit(X_train, y_train)
    predictions = evaluation_model.predict(X_test)

    results = {
        "dataset": str(data_path.relative_to(ROOT))
        if data_path.is_relative_to(ROOT)
        else str(data_path),
        "dataset_rows_after_cleaning": int(len(df)),
        "class_counts": {
            "legitimate": int((y == 0).sum()),
            "phishing": int((y == 1).sum()),
        },
        "test_rows": int(len(y_test)),
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision_phishing": round(
            float(precision_score(y_test, predictions, zero_division=0)), 4
        ),
        "recall_phishing": round(
            float(recall_score(y_test, predictions, zero_division=0)), 4
        ),
        "f1_phishing": round(
            float(f1_score(y_test, predictions, zero_division=0)), 4
        ),
        "confusion_matrix_labels": ["legitimate", "phishing"],
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=[0, 1]
        ).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["legitimate", "phishing"],
            output_dict=True,
            zero_division=0,
        ),
        "evaluation_note": (
            "Metrics are from a random held-out split, not a guarantee of "
            "real-world performance. Duplicate URLs were removed, but "
            "domain/time leakage may still exist."
        ),
    }

    # Train the final inference model on all available labeled data.
    final_model = create_model()
    final_model.fit(X, y)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": final_model,
        "feature_names": FEATURE_NAMES,
        "version": "rf-baseline-1.2",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_rows": int(len(df)),
        "classes": {"legitimate": 0, "phishing": 1},
    }
    joblib.dump(bundle, MODEL_PATH)

    METRICS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("\n=== URL Sentinel: Random Forest Evaluation ===")
    print(f"Rows used: {len(df)}")
    print(f"Train rows: {len(y_train)} | Test rows: {len(y_test)}")
    print(f"Accuracy:          {results['accuracy']:.4f}")
    print(f"Phishing precision: {results['precision_phishing']:.4f}")
    print(f"Phishing recall:    {results['recall_phishing']:.4f}")
    print(f"Phishing F1-score:  {results['f1_phishing']:.4f}")
    print("Confusion matrix (rows=actual, columns=predicted):")
    print(results["confusion_matrix"])
    print(f"\nModel saved to: {MODEL_PATH}")
    print(f"Metrics saved to: {METRICS_PATH}")


if __name__ == "__main__":
    main()
