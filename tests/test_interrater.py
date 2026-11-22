"""Inter-rater script: reading rating files and Cohen's kappa."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import interrater as ir


def test_parse_ratings_reads_rated_lines_and_skips_the_rest():
    text = (
        "# header\n\n 1. abc12345  A  tight scope\n 2. def67890  r  fires on reg query\n 3. 0123abcd  ?  \n"
    )
    assert ir.parse_ratings(text) == {
        "abc12345": ("A", "tight scope"),
        "def67890": ("R", "fires on reg query"),
    }


def test_review_apply_lines_are_not_ratings():
    # A rating file must never double as a decisions file, and the other way round.
    assert ir.parse_ratings("approve abc12345 looks fine\n") == {}


def test_kappa_perfect_chance_and_worse():
    assert ir.cohen_kappa(list("AARR"), list("AARR")) == 1.0
    assert ir.cohen_kappa(list("AARR"), list("ARAR")) == pytest.approx(0.0)
    assert ir.cohen_kappa(list("AARR"), list("RRAA")) == pytest.approx(-1.0)
    assert ir.cohen_kappa(list("AAAA"), list("AAAA")) == 1.0  # both always approve: no chance term to beat
    assert ir.cohen_kappa([], []) is None


def test_kappa_matches_a_worked_example():
    # 10 runs, 8 agreements; both approve 6: p_o = 0.8, p_e = 0.6*0.6 + 0.4*0.4 = 0.52 -> kappa 0.58
    a = list("AAAAAARRRR")
    b = list("AAAAARRRRA")
    assert ir.cohen_kappa(a, b) == pytest.approx((0.8 - 0.52) / (1 - 0.52))
