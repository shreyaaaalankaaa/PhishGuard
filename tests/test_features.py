from feature_extractor import URLFeatureExtractor


def test_feature_extraction_is_deterministic():
    extractor = URLFeatureExtractor()
    url = "https://secure-paypal.example.net/login?verify=1"
    assert extractor.extract_features(url) == extractor.extract_features(url)


def test_ip_and_keywords_are_detected():
    features = URLFeatureExtractor().extract_features("http://203.0.113.10/verify/account")
    assert features["has_ip_host"] == 1
    assert features["has_phishing_term"] == 1


def test_lookalike_brand_domains_are_flagged():
    extractor = URLFeatureExtractor()
    for url in (
        "http://paypa1-secure-login.com.verify-update.ru/signin",
        "https://g00gle.com",
        "https://secure-paypal-login.com/",
    ):
        assert extractor.extract_features(url)["brand_lookalike"] == 1, url


def test_brand_own_domain_is_not_a_lookalike():
    extractor = URLFeatureExtractor()
    for url in ("https://accounts.google.com/signin", "https://www.paypal.com/in/home", "https://github.com"):
        assert extractor.extract_features(url)["brand_lookalike"] == 0, url
