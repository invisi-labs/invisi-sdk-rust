#!/usr/bin/env python3
"""Check the public wallet C ABI in the built native library."""
import pathlib
import subprocess
import sys

library = pathlib.Path(sys.argv[1])
flags = ["-gU"] if sys.platform == "darwin" else ["-D", "-g", "--defined-only"]
output = subprocess.check_output(["nm", *flags, str(library)], text=True)
symbols = {line.split()[-1].removeprefix("_") for line in output.splitlines() if line.split()}
wallet_exports = {symbol for symbol in symbols if symbol.startswith(("invisi_", "privacy_"))}
expected = {"invisi_wallet_execute_batch", "invisi_wallet_free"}
if wallet_exports != expected:
    raise SystemExit(f"Unexpected wallet C ABI: {sorted(wallet_exports ^ expected)}")
print("Current wallet C ABI exports verified")
