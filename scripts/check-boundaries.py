#!/usr/bin/env python3
"""Enforce the six-module production dependency graph and separate native adapter."""
from pathlib import Path
import tomllib
import json

root = Path(__file__).resolve().parents[1]
expected = {
    'invisi-sdk-primitives': set(),
    'invisi-sdk-protocol': {'invisi-sdk-primitives'},
    'invisi-sdk-prover': {'invisi-sdk-primitives', 'invisi-sdk-protocol'},
    'invisi-sdk-rpc': {'invisi-sdk-primitives', 'invisi-sdk-protocol'},
    'invisi-sdk': {'invisi-sdk-primitives', 'invisi-sdk-protocol', 'invisi-sdk-prover', 'invisi-sdk-rpc'},
    # Session exposes protocol DTOs directly; proving is accessed through SDK.
    'invisi-sdk-session': {'invisi-sdk', 'invisi-sdk-primitives', 'invisi-sdk-rpc', 'invisi-sdk-protocol'},
    'invisi-sdk-ipp': {'invisi-sdk-primitives', 'invisi-sdk'},
    'invisi-sdk-ffi': {'invisi-sdk-primitives'},
}
found = {}
for manifest in [root / 'Cargo.toml', *sorted((root / 'crates').glob('*/Cargo.toml'))]:
    config = tomllib.loads(manifest.read_text())
    package = config['package']
    name = package['name']
    assert name in expected, f'Unexpected public crate: {name}'
    assert package['version'] == '1.3.0', f'Version mismatch: {name}'
    dependencies = config.get('dependencies', {})
    internal = {key for key, value in dependencies.items() if key.startswith('invisi-') or isinstance(value, dict) and value.get('package', '').startswith('invisi-')}
    assert internal == expected[name], f'{name}: dependency boundary changed: {internal}'
    for dependency in internal:
        assert dependencies[dependency]['version'] == '=1.3.0'
    if name == 'invisi-sdk-ipp':
        assert dependencies['invisi-sdk'].get('optional') is True
        assert config.get('features', {}).get('default') == []
    if name in {'invisi-sdk-primitives', 'invisi-sdk-protocol'}:
        assert not {'reqwest', 'tokio', 'rusqlite'} & dependencies.keys(), f'{name}: IO dependency'
        for source in (manifest.parent / 'src').rglob('*.rs'):
            text = source.read_text()
            assert 'std::process' not in text and 'reqwest::' not in text, f'{source}: execution/network boundary'
    if name == 'invisi-sdk-rpc':
        assert not {'aes-gcm', 'rusqlite'} & dependencies.keys(), 'RPC must not own encrypted wallet recovery/storage'
    if name in {'invisi-sdk-primitives', 'invisi-sdk-protocol'}:
        for source in (manifest.parent / 'src').rglob('*.rs'):
            text = source.read_text()
            assert 'pub fn build_witness' not in text and 'pub trait OfflineProver' not in text, f'{source}: proving belongs in prover'
    found[name] = manifest
assert found.keys() == expected.keys(), 'Missing public crate'
assert 'pub use invisi_sdk_primitives::*' not in (root / 'crates/invisi-sdk-protocol/src/lib.rs').read_text()
public = json.loads((root / 'crates/invisi-sdk-protocol/assets/circuit-statements.json').read_text())
witness = json.loads((root / 'crates/invisi-sdk-prover/assets/prover/witness-layouts.json').read_text())
assert public == {name: {key: layout[key] for key in ('artifactSha256', 'keys', 'publicInputCount')} for name, layout in witness.items()}, 'Public statement catalog drifted from witness layouts'
print('Eight public crates and six-module production boundaries verified')
