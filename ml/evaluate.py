"""Evaluate a saved URL Sentinel model on a separate labeled CSV."""

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.ml.features import extract_url_features

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "backend" / "models" / "url_model.joblib"

LABEL_MAP = {
    "0": 0, "legitimate": 0, "benign": 0, "safe": 0,
    "1": 1, "phishing": 1, "malicious": 1, "fake": 1, "unsafe": 1,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="Separate labeled test CSV.")
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.is_absolute():
        data_path = ROOT / data_path

    if not MODEL_PATH.exists():
        raise FileNotFoundError("Model not found. Train it first with ml/train.py.")

    df = pd.read_csv(data_path)
    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("CSV must have url and label columns.")

    df = df[["url", "label"]].dropna().copy()
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower().map(LABEL_MAP)
    df = df.dropna().drop_duplicates(subset=["url"])
    df["label"] = df["label"].astype(int)

    if len(df) == 0 or set(df["label"].unique()) != {0, 1}:
        raise ValueError("Test CSV must contain examples of both classes.")

    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    feature_names = bundle["feature_names"]

    X = pd.DataFrame(
        [extract_url_features(url) for url in df["url"]],
        columns=feature_names,
    )
    y = df["label"]
    predictions = model.predict(X)

    print(f"Test dataset: {data_path}")
    print(f"Test rows: {len(df)}")
    print(f"Accuracy: {accuracy_score(y, predictions):.4f}")
    print(f"Phishing precision: {precision_score(y, predictions, zero_division=0):.4f}")
    print(f"Phishing recall: {recall_score(y, predictions, zero_division=0):.4f}")
    print(f"Phishing F1-score: {f1_score(y, predictions, zero_division=0):.4f}")
    print("Confusion matrix (rows=actual, columns=predicted):")
    print(confusion_matrix(y, predictions, labels=[0, 1]))
    print(classification_report(
        y,
        predictions,
        labels=[0, 1],
        target_names=["legitimate", "phishing"],
        zero_division=0,
    ))


if __name__ == "__main__":
    main()
