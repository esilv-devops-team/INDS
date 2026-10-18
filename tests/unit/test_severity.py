import pytest

from backend.services.severity import classify_severity


@pytest.mark.parametrize(
    "score, expected",
    [
        (0, "Low"),
        (29, "Low"),
        (30, "Medium"),
        (54, "Medium"),
        (55, "High"),
        (79, "High"),
        (80, "Critical"),
        (100, "Critical"),
    ],
)
def test_levels_and_boundaries(score, expected):
    assert classify_severity(score) == expected


@pytest.mark.parametrize(
    "score, expected",
    [
        (95, "High"),
        (60, "Medium"),
        (40, "Low"),
        (10, "Low"),
    ],
)
def test_trusted_device_is_one_level_lower(score, expected):
    assert classify_severity(score, trusted=True) == expected


@pytest.mark.parametrize("score", [-1, 101])
def test_score_out_of_range_is_rejected(score):
    with pytest.raises(ValueError):
        classify_severity(score)