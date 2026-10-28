
"""URL Sentinel API: safe URL validation and ML-backed scanning."""

import ipaddress
import logging
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from app.ml.features import FEATURE_NAMES, extract_url_features
from app.api.diagnostics import router as diagnostics_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("url-sentinel")

APP_DIR = Path(__file__).resolve().parent
MODEL_PATH = Path(
    os.getenv(
        "URL_SENTINEL_MODEL_PATH",
        str(APP_DIR.parent / "models" / "url_model.joblib"),
    )
)

app = FastAPI(
    title="URL Sentinel API",
    description=(
        "Lexical URL analysis, machine-learning risk detection, "
        "and website diagnostics."
    ),
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?|chrome-extension://.*",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# New diagnostics endpoint; existing scan endpoints remain unchanged.
app.include_router(diagnostics_router)

model_bundle = None
model_load_error = None


def load_model():
    """Load only a locally available, trusted model artifact."""
    global model_bundle, model_load_error

    if not MODEL_PATH.is_file():
        model_bundle = None
        model_load_error = "Trained model artifact has not been created yet."
        logger.warning("%s", model_load_error)
        return

    try:
        bundle = joblib.load(MODEL_PATH)

        if not isinstance(bundle, dict) or "model" not in bundle:
            raise ValueError(
                "Model file must contain a dictionary with a 'model' key."
            )

        model_bundle = bundle
        model_load_error = None
        logger.info("Loaded model artifact: %s", MODEL_PATH)

    except Exception:
        model_bundle = None
        model_load_error = "Model artifact could not be loaded."
        logger.exception("Failed to load model artifact")


load_model()


class ScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()

        if any(ord(char) < 32 for char in value):
            raise ValueError("URL must not contain control characters.")

        parsed = urlsplit(value)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.hostname:
            raise ValueError("URL must contain a valid hostname.")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError(
                "URLs containing embedded credentials are not supported."
            )

        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("URL contains an invalid port.") from exc

        hostname = parsed.hostname

        if not re.fullmatch(r"[a-zA-Z0-9.\-\[\]:%]+", hostname):
            try:
                hostname.encode("idna")
            except UnicodeError as exc:
                raise ValueError("URL contains an invalid hostname.") from exc

        return value


def build_indicators(url: str) -> list[str]:
    """Return explainable lexical observations, not a verdict by themselves."""
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    indicators = []

    try:
        ipaddress.ip_address(hostname)
        indicators.append(
            "The hostname is an IP address rather than a domain name."
        )
    except ValueError:
        pass

    if "@" in url:
        indicators.append(
            "The URL contains an @ symbol, which can obscure the destination."
        )

    if "xn--" in hostname:
        indicators.append(
            "The hostname contains an internationalized/punycode label."
        )

    if "http" in hostname:
        indicators.append("The hostname contains the text 'http'.")

    if len(url) > 100:
        indicators.append("The URL is unusually long.")

    hostname_digit_ratio = (
        sum(char.isdigit() for char in hostname) / max(len(hostname), 1)
    )
    if hostname_digit_ratio > 0.25:
        indicators.append(
            "The hostname contains a high proportion of digits."
        )

    if parsed.scheme.lower() != "https":
        indicators.append(
            "The URL does not use HTTPS; this alone does not prove it is malicious."
        )

    if not indicators:
        indicators.append(
            "No basic lexical warning pattern was detected; "
            "this does not guarantee safety."
        )

    return indicators


@app.get("/")
def root():
    return {
        "name": "URL Sentinel API",
        "status": "online",
        "docs": "/docs",
    }


@app.get("/api/v1/health")
def health():
    return {
        "status": "ok",
        "service": "URL Sentinel API",
        "model_loaded": model_bundle is not None,
        "model_version": (
            model_bundle.get("version", "unknown")
            if model_bundle is not None
            else None
        ),
        "message": (
            "Model ready."
            if model_bundle is not None
            else "API is running, but a trained model is not available yet."
        ),
    }


@app.post("/api/v1/scans")
def scan_url(request: ScanRequest):
    # This endpoint analyzes the URL string only. It does not fetch the site.
    if model_bundle is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "MODEL_NOT_READY",
                "message": (
                    "The API is running, but the trained ML model is not ready. "
                    "No prediction was made."
                ),
            },
        )

    try:
        features = extract_url_features(request.url)
        feature_names = model_bundle.get("feature_names", FEATURE_NAMES)
        row = pd.DataFrame([features]).reindex(
            columns=feature_names,
            fill_value=0,
        )
        model = model_bundle["model"]

        prediction = model.predict(row)[0]
        classes = list(getattr(model, "classes_", []))
        probabilities = (
            model.predict_proba(row)[0]
            if hasattr(model, "predict_proba")
            else None
        )

        label = str(prediction).strip().lower()

        if label in {"1", "phishing", "malicious", "fake", "unsafe"}:
            classification = "malicious"
        elif label in {"0", "legitimate", "benign", "safe", "genuine"}:
            classification = "legitimate"
        else:
            raise HTTPException(
                status_code=500,
                detail="The model returned an unsupported class label.",
            )

        risk_score = None

        if probabilities is not None and classes:
            malicious_indexes = [
                index
                for index, item in enumerate(classes)
                if str(item).strip().lower()
                in {"1", "phishing", "malicious", "fake", "unsafe"}
            ]

            if malicious_indexes:
                risk_score = round(
                    float(
                        max(probabilities[index] for index in malicious_indexes)
                    ) * 100,
                    2,
                )

        return {
            "url": request.url,
            "classification": classification,
            "risk_score": risk_score,
            "model_version": model_bundle.get("version", "unknown"),
            "indicators": build_indicators(request.url),
            "message": (
                "This is a model-based risk estimate, not a guarantee of safety."
            ),
        }

    except HTTPException:
        raise
    except Exception:
        logger.exception("URL scan failed")
        raise HTTPException(
            status_code=500,
            detail=(
                "The scan could not be completed. "
                "No reliable prediction is available."
            ),
        )
