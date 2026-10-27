"""Comparable anomaly detectors behind one interface (FR-3, RQ1).

Every detector scores Detection-Window user-days from their baseline-normalised
features and returns a value in [0, 1]. ML detectors are trained only on
Baseline-Window days (novelty detection), and their raw scores are calibrated to
"the share of held-out normal days that are less unusual than this one", so all
detectors read on the same scale.
"""

from __future__ import annotations

from collections.abc import Callable

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

from ueba.baselines import compute_baselines, zscores

Z_CLIP = (-5.0, 20.0)
MAX_FIT_ROWS = 20_000
MAX_SVM_ROWS = 4_000


def _baseline_zscore(train: np.ndarray, calib: np.ndarray, test: np.ndarray, seed: int) -> np.ndarray:
    peak = np.clip(test.max(axis=1), 0, None)
    return np.asarray(peak / (peak + 5.0))


def _calibrated(model_score: Callable[[np.ndarray], np.ndarray], calib: np.ndarray, test: np.ndarray) -> np.ndarray:
    """Higher model_score = more normal (sklearn convention); convert to an empirical anomaly percentile."""
    ref = np.sort(model_score(calib))
    test_scores = model_score(test)
    more_normal = len(ref) - np.searchsorted(ref, test_scores, side="left")
    return np.asarray(more_normal / len(ref))


def _isolation_forest(train: np.ndarray, calib: np.ndarray, test: np.ndarray, seed: int) -> np.ndarray:
    model = IsolationForest(n_estimators=200, random_state=seed).fit(train)
    return _calibrated(model.score_samples, calib, test)


def _lof(train: np.ndarray, calib: np.ndarray, test: np.ndarray, seed: int) -> np.ndarray:
    model = LocalOutlierFactor(n_neighbors=35, novelty=True).fit(train)
    return _calibrated(model.score_samples, calib, test)


def _ocsvm(train: np.ndarray, calib: np.ndarray, test: np.ndarray, seed: int) -> np.ndarray:
    model = OneClassSVM(nu=0.05, gamma="scale").fit(train[:MAX_SVM_ROWS])
    return _calibrated(model.decision_function, calib, test)


Detector = Callable[[np.ndarray, np.ndarray, np.ndarray, int], np.ndarray]

DETECTORS: dict[str, Detector] = {
    "baseline_zscore": _baseline_zscore,
    "isolation_forest": _isolation_forest,
    "lof": _lof,
    "ocsvm": _ocsvm,
}


def score_user_days(features: pd.DataFrame, detector: str = "isolation_forest", seed: int = 0) -> pd.Series:
    """Anomaly score in [0, 1] for each Detection-Window row of `features` (same index)."""
    if detector not in DETECTORS:
        raise ValueError(f"unknown detector {detector!r}; choose from {sorted(DETECTORS)}")
    z = zscores(features, compute_baselines(features)).clip(*Z_CLIP)

    in_base = features["in_baseline"].to_numpy()
    base = z[in_base].to_numpy()
    rng = np.random.default_rng(seed)
    base = base[rng.permutation(len(base))[: MAX_FIT_ROWS + MAX_FIT_ROWS // 4]]
    split = int(len(base) * 0.8)
    train, calib = base[:split], base[split:]

    test_index = features.index[~in_base]
    scores = DETECTORS[detector](train, calib, z.loc[test_index].to_numpy(), seed)
    return pd.Series(np.clip(scores, 0.0, 1.0), index=test_index, name=detector)
