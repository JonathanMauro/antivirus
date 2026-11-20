import math
from pathlib import Path

from tkv_ml.features import FEATURE_NAMES, extract, shannon_entropy


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0
    assert math.isclose(shannon_entropy(bytes(range(256)) * 4), 8.0)


def test_non_pe_file(tmp_path: Path):
    f = tmp_path / "texto.txt"
    f.write_bytes(b"ola mundo")
    feats = extract(f)
    assert set(feats) == set(FEATURE_NAMES)
    assert feats["is_pe"] == 0
    assert feats["size"] == 9


def test_broken_pe_does_not_crash(tmp_path: Path):
    f = tmp_path / "quebrado.exe"
    f.write_bytes(b"MZ" + b"\x00" * 10)
    assert extract(f)["is_pe"] == 0
