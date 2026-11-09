#!/usr/bin/env python3
"""Reject CJK text in tracked and newly added SDK source/documentation."""
import pathlib
import re
import subprocess
import sys

pattern = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")
paths = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
).decode().split("\0")
failed = False
for name in sorted(set(paths)):
    path = pathlib.Path(name)
    if not name or not path.is_file() or path.suffix not in {".rs", ".md", ".toml", ".json", ".py", ".yml", ".yaml", ".h"}:
        continue
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if pattern.search(line):
            print(f"{name}:{number}: non-English CJK text is not allowed")
            failed = True
sys.exit(1 if failed else 0)
