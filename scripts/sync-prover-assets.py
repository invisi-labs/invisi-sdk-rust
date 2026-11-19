#!/usr/bin/env python3
"""Authenticate a Core prover-assets release and seed the SDK's external disk cache.

No heavy resources are copied into any crate. Update the reviewed trust anchor
with --update-pin only when accepting a new Core public-resource release.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / 'crates/invisi-sdk-prover/assets/prover/resource-release.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release_directory', type=Path)
    parser.add_argument('--cache', type=Path, default=ROOT / '.cache/prover-assets')
    parser.add_argument('--update-pin', action='store_true')
    parser.add_argument('--initial-payment', action='store_true', help='Authenticate the separate combined Credit circuit set')
    args = parser.parse_args()
    pin_path = PIN.with_name('initial-payment-resource-release.json') if args.initial_payment else PIN
    raw = (args.release_directory / 'index.json').read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    index = json.loads(raw)
    if len(raw) > 1024 * 1024 or index['format'] != 'invisi.prover-assets.v1' or index['noirVersion'] != '1.0.0' or index['bbVersion'] != '6.0.0':
        raise SystemExit('Unsupported resource index')
    if not args.update_pin and json.loads(pin_path.read_bytes())['indexSha256'] != digest:
        raise SystemExit('Untrusted index: review the release before updating its pin')
    objects = {}
    for logical, entry in index['files'].items():
        if not all(p and p not in ('.', '..') for p in logical.split('/')) or logical.startswith('/') or '\\' in logical:
            raise SystemExit('Invalid logical resource path')
        extension = 'json' if logical.endswith('.json') else 'vk' if logical.endswith(('.vk', '/vk')) else None
        if not extension or not re.fullmatch('[0-9a-f]{64}', entry['sha256']) or type(entry['size']) is not int or not 0 < entry['size'] <= 512 * 1024 * 1024:
            raise SystemExit('Invalid resource metadata')
        filename = entry['sha256'] + '.' + extension
        path = args.release_directory / filename
        if path.stat().st_size != entry['size'] or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            raise SystemExit('Resource integrity mismatch: ' + logical)
        objects[filename] = path
    args.cache.mkdir(parents=True, exist_ok=True)
    for name, source in objects.items():
        temporary = args.cache / ('.' + name + '.tmp')
        shutil.copyfile(source, temporary)
        temporary.replace(args.cache / name)
    (args.cache / (digest + '.index.json')).write_bytes(raw)
    if args.update_pin:
        pin_path.write_text(json.dumps({'indexSha256': digest, 'noirVersion': '1.0.0', 'bbVersion': '6.0.0'}, separators=(',', ':')) + '\n')
    print(f'Authenticated {len(index["files"])} public resources; external cache: {args.cache}; index: {digest}')


if __name__ == '__main__':
    main()
