from engine.engine.windows import WindowStore


def test_prune_by_age():
    s = WindowStore()
    s.push("k", 100.0, "a", age=10.0)
    s.push("k", 105.0, "b", age=10.0)
    s.push("k", 112.0, "c", age=10.0)  # prunes the 100.0 entry
    vals = [e.value for e in s.window("k", 112.0, 10.0)]
    assert vals == ["b", "c"]


def test_maxlen_cap():
    s = WindowStore()
    for i in range(50):
        s.push("k", float(i), i, age=1000, maxlen=10)
    assert len(s.window("k", 50.0, 1000)) == 10


def test_multiple_keys_independent():
    s = WindowStore()
    s.push("a", 1.0, 1)
    s.push("b", 1.0, 2)
    assert len(s.window("a", 2.0, 100)) == 1
    assert len(s.window("b", 2.0, 100)) == 1
