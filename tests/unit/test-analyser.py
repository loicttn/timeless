import sys
sys.path.append(".")
from src.analyzer import Analyzer


def test_init() -> None:
    analyzer = Analyzer("test")
    infos = analyzer.get()
    assert infos.get("name") == "test"
    assert infos.get("magic_number") is None
    assert infos.get("format") is None
    assert infos.get("bits") is None
    assert infos.get("endianness") is None
    assert infos.get("size") is None
    assert infos.get("content") is None
