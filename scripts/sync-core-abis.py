#!/usr/bin/env python3
"""Import current Core ABI schemas without modifying authenticated proving assets."""
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
core = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root.parent / 'invisi-core'
names = ('InvisiCore', 'InvisiCoreFactory', 'InvisiAddressRegistry', 'IERC20',
         'VerifierRouter', 'CreditVerifierRouter', 'BroadcasterRegistry')
# Authenticate the complete input set before replacing any SDK schema.
rows = {}
for name in names:
    source = core / 'contracts/out' / (name + '.sol') / (name + '.json')
    abi = json.loads(source.read_text())['abi']
    if not isinstance(abi, list):
        raise ValueError('Invalid compiler ABI: ' + name)
    rows[name] = abi
for name, abi in rows.items():
    path = root / 'crates/invisi-sdk-protocol/src/protocol/abi' / (name + '.abi.json')
    path.write_text(json.dumps(abi, indent=2) + '\n')
print('Synced 7 current Core ABIs')
