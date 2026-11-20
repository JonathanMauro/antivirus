"""Linha de base de detecção de anomalias com Isolation Forest.

Treina SOMENTE com arquivos considerados legítimos (ex.: C:\\Windows\\System32)
e aponta o quão "fora do padrão" um arquivo novo está. Não é um classificador
de malware; é um sinal a mais para o Risk Score.

Uso:
    python -m tkv_ml.anomaly train  <features_limpos.csv> <modelo.joblib>
    python -m tkv_ml.anomaly score  <modelo.joblib> <features.csv>
"""

from __future__ import annotations

import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from .features import FEATURE_NAMES


def train(features_csv: Path, model_path: Path, contamination: float = 0.01) -> None:
    df = pd.read_csv(features_csv)
    model = IsolationForest(
        n_estimators=200, contamination=contamination, random_state=42, n_jobs=-1
    )
    model.fit(df[FEATURE_NAMES])
    joblib.dump({"model": model, "features": FEATURE_NAMES}, model_path)
    print(f"modelo treinado com {len(df)} amostras -> {model_path}")


def score(model_path: Path, features_csv: Path) -> pd.DataFrame:
    bundle = joblib.load(model_path)
    df = pd.read_csv(features_csv)
    # score_samples: quanto MENOR, mais anômalo.
    df["anomaly_score"] = bundle["model"].score_samples(df[bundle["features"]])
    return df.sort_values("anomaly_score")[["path", "sha256", "anomaly_score"]]


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "train":
        train(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == "score":
        print(score(Path(sys.argv[2]), Path(sys.argv[3])).head(30).to_string(index=False))
    else:
        print(__doc__)
        sys.exit(2)
