"""The committed model must load and behave sensibly on obvious cases."""
from ml_pipeline import PhishingDetectionPipeline


def test_shipped_model_loads():
    info = PhishingDetectionPipeline().get_model_info()
    assert info["engine"] == "machine_learning"


def test_obvious_phishing_is_flagged():
    pipeline = PhishingDetectionPipeline()
    for url in (
        "http://paypa1-secure-login.com.verify-update.ru/signin?acct=1",
        "http://198.51.100.42/verify-account/login",
    ):
        assert pipeline.predict(url)["prediction"] == "phishing", url


def test_popular_sites_are_not_flagged():
    pipeline = PhishingDetectionPipeline()
    for url in ("https://github.com", "https://accounts.google.com/signin", "https://en.wikipedia.org/wiki/Phishing"):
        assert pipeline.predict(url)["prediction"] == "legitimate", url


def test_model_with_old_feature_set_is_ignored(tmp_path, monkeypatch):
    import joblib
    import pandas as pd
    from sklearn.dummy import DummyClassifier

    stale = DummyClassifier().fit(pd.DataFrame({"url_length": [1.0, 2.0]}), [0, 1])
    path = tmp_path / "phishguard.joblib"
    joblib.dump({"model": stale, "metadata": {}}, path)
    monkeypatch.setattr(PhishingDetectionPipeline, "MODEL_PATH", path)
    monkeypatch.setattr(PhishingDetectionPipeline, "MODEL_DIR", tmp_path)
    assert PhishingDetectionPipeline().get_model_info()["engine"] == "validated_heuristic_fallback"
