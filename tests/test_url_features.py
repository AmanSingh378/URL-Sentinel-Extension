from app.ml.features import FEATURE_NAMES, extract_url_features


def test_feature_count_matches_trained_model():
    assert len(FEATURE_NAMES) == 18


def test_trailing_slash_does_not_change_selected_features():
    urls = [
        ("https://github.com", "https://github.com/"),
        ("https://www.google.com", "https://www.google.com/"),
    ]

    keys = [
        "url_length",
        "hostname_length",
        "num_dots",
        "num_subdomains",
        "path_length",
        "num_slashes",
        "hostname_entropy",
    ]

    for first, second in urls:
        a = extract_url_features(first)
        b = extract_url_features(second)

        for key in keys:
            assert a[key] == b[key], f"{key} differs for {first} and {second}"


def test_www_normalization_for_selected_features():
    first = extract_url_features("https://github.com")
    second = extract_url_features("https://www.github.com")

    keys = [
        "hostname_length",
        "num_dots",
        "num_subdomains",
        "hostname_entropy",
    ]

    for key in keys:
        assert first[key] == second[key], f"{key} differs"
