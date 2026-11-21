#!/usr/bin/env python3
"""Authenticate exported Core VK JSON/binaries and emit only recursive trust metadata.

This does not accept new resource pins or commitments: review those separately.
The manifest names VK files relative to the supplied export root.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
METADATA = ROOT / 'crates/invisi-sdk-prover/assets/prover/recursive-key.json'
CATALOG = ROOT / 'crates/invisi-sdk-protocol/assets/circuit-statements.json'
MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def require(condition, message):
    if not condition:
        raise ValueError(message)


def field(value):
    require(isinstance(value, str) and re.fullmatch(r'0x[0-9a-fA-F]{64}', value) is not None,
            'Malformed recursive VK field')
    require(int(value, 16) < MODULUS, 'Noncanonical recursive VK field')
    return value.lower()


def read_export(root, path):
    require(isinstance(path, str) and path and not path.startswith('/') and '\\' not in path
            and all(part not in ('', '.', '..') for part in path.split('/')), 'Invalid export path')
    resolved = (root / path).resolve()
    require(resolved.is_relative_to(root.resolve()), 'Export path escapes root')
    return resolved.read_bytes()


def authenticate_metadata(root, manifest, trusted, catalog):
    require(manifest.get('complete') is True and manifest.get('bbVersion') == '6.0.0', 'Unsupported export manifest')
    result = {}
    for entry in manifest.get('entries', []):
        match = re.fullmatch(r'transact_user_slots([1-9]|10)', entry.get('name', ''))
        if not match:
            continue
        capacity = match.group(1)
        require(capacity not in result, 'Duplicate recursive key')
        key = entry['recursive']
        require(key['target'] == 'noir-recursive', 'Wrong recursive key target')
        binary = read_export(root, key['vk'])
        digest = hashlib.sha256(binary).hexdigest()
        require(digest == key['vkSha256'] == catalog[entry['name']]['keys']['noir-recursive'], 'Untrusted recursive binary VK')
        raw = read_export(root, key['vkJson'])
        require(hashlib.sha256(raw).hexdigest() == key['vkJsonSha256'], 'Corrupt exported VK JSON')
        exported = json.loads(raw)
        require(exported.get('bb_version') == '6.0.0' and exported.get('scheme') == 'ultra_honk', 'Unsupported VK JSON')
        words = exported.get('vk')
        require(isinstance(words, list) and len(words) == 115 and len(binary) == 115 * 32, 'Recursive VK width mismatch')
        words = [field(word) for word in words]
        require(bytes.fromhex(''.join(word[2:] for word in words)) == binary, 'Recursive VK JSON/binary mismatch')
        key_hash = field(exported['hash'])
        commitment = field(key['innerVkCommitment'])
        # The reviewed key hash and outer-circuit commitment are trust anchors.
        # Authenticating the exact binary and JSON fields binds both to those pins;
        # runtime loading independently recomputes the Poseidon commitment.
        require(key_hash == field(trusted[capacity]['keyHash']), 'Untrusted recursive key hash')
        require(commitment == field(trusted[capacity]['innerVkCommitment']), 'Untrusted recursive key commitment')
        result[capacity] = {'keyHash': key_hash, 'innerVkCommitment': commitment}
    require(set(result) == {str(capacity) for capacity in range(1, 11)}, 'Incomplete recursive key export')
    return {str(capacity): result[str(capacity)] for capacity in range(1, 11)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('export_root', type=Path)
    parser.add_argument('--manifest', default='circuits/transact/manifest.json')
    args = parser.parse_args()
    manifest = json.loads(read_export(args.export_root, args.manifest))
    metadata = authenticate_metadata(args.export_root, manifest, json.loads(METADATA.read_bytes()), json.loads(CATALOG.read_bytes()))
    METADATA.write_text(json.dumps(metadata, indent=2) + '\n')
    print('Authenticated 10 recursive verification keys; emitted hash/commitment metadata only')


if __name__ == '__main__':
    main()
