import numpy as np
import pandas as pd
import pytest

from ueba.detectors import DETECTORS, score_user_days
from ueba.features import build_daily_features
from ueba.generator import GeneratorConfig, SyntheticData, generate


@pytest.fixture(scope="module")
def synth() -> SyntheticData:
    return generate(GeneratorConfig(n_users=60, seed=11))


@pytest.fixture(scope="module")
def features(synth: SyntheticData) -> pd.DataFrame:
    return build_daily_features(synth.events, synth.users, synth.baseline_end)


def test_registry_has_the_must_and_should_detectors() -> None:
    assert set(DETECTORS) == {"baseline_zscore", "isolation_forest", "lof", "ocsvm"}


@pytest.mark.parametrize("name", sorted(DETECTORS))
def test_each_detector_scores_every_detection_day_in_0_to_1(features: pd.DataFrame, name: str) -> None:
    scores = score_user_days(features, name, seed=0)
    detection = features[~features["in_baseline"]]
    assert len(scores) == len(detection)
    assert scores.between(0, 1).all()
    assert scores.index.equals(detection.index)


@pytest.mark.parametrize("name", ["baseline_zscore", "isolation_forest"])
def test_anomalous_users_score_higher_than_normal_users(synth: SyntheticData, features: pd.DataFrame, name: str) -> None:
    scores = score_user_days(features, name, seed=0)
    per_user = scores.groupby(features.loc[scores.index, "user_id"]).max()
    labels = synth.labels.set_index("user_id")
    anomalous = per_user[labels.loc[per_user.index, "is_anomalous"].to_numpy()]
    normal = per_user[(labels.loc[per_user.index, "scenario"] == "normal").to_numpy()]
    assert anomalous.median() > normal.median()


def test_scores_are_reproducible_for_a_seed(features: pd.DataFrame) -> None:
    a = score_user_days(features, "isolation_forest", seed=3)
    b = score_user_days(features, "isolation_forest", seed=3)
    assert np.allclose(a, b)


def test_unknown_detector_is_rejected(features: pd.DataFrame) -> None:
    with pytest.raises(ValueError):
        score_user_days(features, "magic")
