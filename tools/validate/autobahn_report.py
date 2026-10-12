#!/usr/bin/env python3
"""Summarise an Autobahn|Testsuite client report (index.json).

usage: autobahn_report.py INDEX_JSON AGENT [EXPECTED_FILE]

A case passes when its behavior and behaviorClose are OK, NON-STRICT or
INFORMATIONAL.  Anything else (FAILED, UNIMPLEMENTED, a missing result) is
listed.  EXPECTED_FILE names case ids, one per line ('#' starts a comment),
whose non-pass is understood and justified; those are reported but do not fail
the run.  Exit status 0 when every non-pass is expected.
"""
import json
import sys

OK = {"OK", "NON-STRICT", "INFORMATIONAL"}


def main():
    path, agent = sys.argv[1], sys.argv[2]
    expected = set()
    if len(sys.argv) > 3:
        try:
            for line in open(sys.argv[3]):
                line = line.split("#")[0].strip()
                if line:
                    expected.add(line.split()[0])
        except OSError:
            pass
    try:
        data = json.load(open(path))[agent]
    except (OSError, KeyError, ValueError) as e:
        print(f"autobahn: no report for agent {agent}: {e}")
        return 1
    counts = {}
    bad = []
    for case, r in sorted(data.items(), key=lambda kv: [int(x) for x in kv[0].split(".")]):
        b, bc = r.get("behavior"), r.get("behaviorClose")
        counts[b] = counts.get(b, 0) + 1
        if b not in OK or bc not in OK:
            bad.append((case, b, bc))
    print("autobahn: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    unexpected = [x for x in bad if x[0] not in expected]
    for case, b, bc in bad:
        tag = "expected" if case in expected else "UNEXPECTED"
        print(f"autobahn: {tag} {case} behavior={b} close={bc}")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
