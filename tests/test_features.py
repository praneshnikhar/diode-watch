from engine.engine.features import dga_features, ngram_anomaly, shannon_entropy


def test_entropy_bounds():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    e = shannon_entropy("abcd")
    assert e == 2.0


def test_entropy_random_high():
    e = shannon_entropy("qxjvkrlmzqpw")
    assert e > 3.0


def test_ngram_anomaly_legit_low():
    assert ngram_anomaly("google") < 0.5


def test_dga_features_shape():
    f = dga_features("qxjvkrlmzqpw.xyz")
    assert set(f) == {
        "entropy", "length", "ngram_anomaly", "digit_ratio", "vowel_ratio",
        "label_count", "tld_suspicious", "is_hex",
    }
    assert f["tld_suspicious"] == 1.0
    assert f["length"] == 12
    assert f["is_hex"] == 0.0


def test_dga_features_hex():
    f = dga_features("0a1b2c3d4e5f6789.com")
    assert f["is_hex"] == 1.0
    assert f["digit_ratio"] > 0.3
