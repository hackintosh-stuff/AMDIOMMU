#!/usr/bin/env python3
"""R65 host model for two independent domain callbacks and one shared PM cycle."""
from itertools import permutations

def run(suspend_order, resume_order):
    domains = {n: {"suspend": False, "resume": False, "accepting": True} for n in ("A", "B")}
    controller = {"ready": True, "suspended": False, "stop": 0, "start": 0}
    for name in suspend_order:
        d = domains[name]
        assert d["accepting"] and controller["ready"]
        d["accepting"] = False
        d["suspend"] = True  # that domain's invalidation CompletionWait completed
        if all(x["suspend"] for x in domains.values()):
            controller["ready"] = False
            controller["suspended"] = True
            controller["stop"] += 1
    assert controller["stop"] == 1 and controller["suspended"]
    for name in resume_order:
        d = domains[name]
        if controller["suspended"]:
            assert all(x["suspend"] for x in domains.values())
            controller["suspended"] = False
            controller["ready"] = True
            controller["start"] += 1
        assert controller["ready"]
        d["resume"] = True  # this domain's device/domain CW completed
        d["accepting"] = True
    assert controller["start"] == 1
    assert all(x["resume"] and x["accepting"] for x in domains.values())
    return True

if __name__ == "__main__":
    for a in permutations(("A", "B")):
        for b in permutations(("A", "B")):
            assert run(a, b)
    print("R65 coordinator model: 4 callback orders passed")
