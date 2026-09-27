"""Converts a pytest junit XML file into run.sh result lines (STATUS<TAB>suite::test)."""
import sys
import xml.etree.ElementTree as ET

path, suite, out = sys.argv[1], sys.argv[2], sys.argv[3]
with open(out, "a") as f:
    for tc in ET.parse(path).iter("testcase"):
        name = tc.get("name")
        mod = tc.get("classname", "").rsplit(".", 1)[-1]
        full = f"{mod}::{name}" if mod else name
        skip = tc.find("skipped")
        if tc.find("failure") is not None or tc.find("error") is not None:
            st = "FAIL"
        elif skip is not None and skip.get("type") == "pytest.xfail":
            st = "XFAIL"
        elif skip is not None:
            st = "SKIP"
        else:
            st = "PASS"
        f.write(f"{st}\t{suite}::{full}\n")
        print(f"{st:<5} {suite}::{full}")
