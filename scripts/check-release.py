#!/usr/bin/env python3
"""Build and test distributable crates against an isolated local registry source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ORDER = ['invisi-sdk-primitives', 'invisi-sdk-protocol', 'invisi-sdk-prover', 'invisi-sdk-rpc', 'invisi-sdk', 'invisi-sdk-session', 'invisi-sdk-ffi']


def run(args, **kwargs):
    print('+', ' '.join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def check_archive_artifacts(contents, name):
    allowed = {}
    if name == 'invisi-sdk-prover':
        manifest_member = next(member for member in contents.getmembers() if member.name.endswith('/provenance/manifest.json'))
        manifest = json.load(contents.extractfile(manifest_member))
        for circuit in manifest['circuits']:
            for key in ('artifact', 'vk'):
                allowed['provenance/' + circuit[key]] = circuit[key + 'Sha256']
    seen = set()
    for member in contents.getmembers():
        parts = Path(member.name).parts[1:]
        relative = '/'.join(parts)
        forbidden = any(part in {'target', 'vendor', '.git', '.cache', '.local'} for part in parts)
        if forbidden and relative not in allowed:
            raise RuntimeError(f'Forbidden package artifact: {member.name}')
        if member.name.endswith(('.sqlite', '.pk', '.proof', '.env')) or not member.isfile():
            raise RuntimeError(f'Private/generated artifact: {member.name}')
        if relative in allowed:
            if hashlib.sha256(contents.extractfile(member).read()).hexdigest() != allowed[relative]:
                raise RuntimeError(f'Runtime artifact digest mismatch: {member.name}')
            seen.add(relative)
    if seen != allowed.keys():
        raise RuntimeError('Missing authenticated public runtime artifacts')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, help='Retain local package artifacts here')
    parser.add_argument('--vendor-dir', type=Path, help='Reuse dependencies previously created by cargo vendor --locked')
    options = parser.parse_args()
    run(['python3', ROOT / 'scripts/check-boundaries.py'], cwd=ROOT)
    fixture_pairs = [
        ('crates/invisi-sdk-protocol/assets/gas/measured-model.json', 'tests/fixtures/measured-model.json'),
        ('crates/invisi-sdk-protocol/assets/gas/model-validation.json', 'tests/fixtures/model-validation.json'),
        ('crates/invisi-sdk-rpc/testdata/golden-vectors.json', 'testdata/provenance-golden-vectors.json'),
        ('crates/invisi-sdk-prover/provenance/manifest.json', 'provenance/manifest.json'),
        ('crates/invisi-sdk-prover/provenance/manifest.json', 'crates/invisi-sdk-session/testdata/source-manifest.json'),
        ('crates/invisi-sdk-protocol/src/provenance-testdata/golden-vectors.json', 'crates/invisi-sdk-rpc/testdata/golden-vectors.json'),
        ('crates/invisi-sdk-protocol/src/provenance-testdata/golden-vectors.json', 'crates/invisi-sdk-prover/src/provenance-testdata/golden-vectors.json'),
        ('crates/invisi-sdk-rpc/testdata/provenance-recovery.json', 'crates/invisi-sdk-session/testdata/provenance-recovery.json'),
        ('tests/fixtures/wallet-wire-vectors.json', 'crates/invisi-sdk-ffi/tests/fixtures/wallet-wire-vectors.json'),
    ]
    for original, packaged in fixture_pairs:
        if (ROOT / original).read_bytes() != (ROOT / packaged).read_bytes():
            raise RuntimeError(f'Packaged fixture drift: {packaged}')
    work = options.work_dir or Path(tempfile.mkdtemp(prefix='invisi-release-'))
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    vendor = options.vendor_dir.resolve() if options.vendor_dir else work / 'registry'
    if not options.vendor_dir:
        run(['cargo', 'vendor', '--locked', vendor], cwd=ROOT, stdout=subprocess.DEVNULL)
    # Registry package versions are immutable to Cargo. Reusing compiled artifacts
    # would hide source changes while validating an unpublished version repeatedly.
    target = work / 'target'
    if target.exists():
        shutil.rmtree(target)
    environment = os.environ.copy()
    environment['CARGO_TARGET_DIR'] = str(work / 'target')
    config = work / 'registry.toml'
    config.write_text('[source.crates-io]\nreplace-with = "release-local"\n[source.release-local]\ndirectory = ' + json.dumps(str(vendor)) + '\n')
    # Bootstrap directory-source entries from precisely the allowlisted package files.
    # Package verification below replaces each bootstrap entry with the actual archive.
    for name in ORDER:
        source = ROOT if name == 'invisi-sdk' else ROOT / 'crates' / name
        package = vendor / name
        if package.exists():
            shutil.rmtree(package)
        package.mkdir()
        result = run(['cargo', 'package', '--list', '--allow-dirty', '--manifest-path', source / 'Cargo.toml'], cwd=ROOT, capture_output=True, text=True)
        for relative in result.stdout.splitlines():
            path = source / relative
            if path.is_file() and relative not in ['Cargo.toml.orig', 'Cargo.lock']:
                destination = package / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
        manifest = (package / 'Cargo.toml').read_text()
        manifest = re.sub(r'path = "[^"]+", ', '', manifest)
        manifest = re.sub(r'\[workspace\]\n.*?(?=\n\[|\Z)', '', manifest, flags=re.S)
        (package / 'Cargo.toml').write_text(manifest)
        (package / '.cargo-checksum.json').write_text(json.dumps({'files': {}, 'package': None}))
    for name in ORDER:
        source = ROOT if name == 'invisi-sdk' else ROOT / 'crates' / name
        run(['cargo', '--config', config, 'package', '--locked', '--offline', '--allow-dirty', '--manifest-path', source / 'Cargo.toml'], cwd=ROOT, env=environment)
        archive = work / 'target' / 'package' / f'{name}-1.2.4.crate'
        destination = vendor / name
        shutil.rmtree(destination)
        unpacked = work / 'unpacked' / f'{name}-1.2.4'
        if unpacked.exists():
            shutil.rmtree(unpacked)
        with tarfile.open(archive) as contents:
            check_archive_artifacts(contents, name)
            contents.extractall(work / 'unpacked', filter='data')
        # Cargo archives normalize mtimes; refresh them so repeated local checks
        # cannot reuse a stale test binary after an archive's contents change.
        for path in unpacked.rglob('*'):
            if path.is_file():
                os.utime(path, None)
        metadata = tomllib.loads((unpacked / 'Cargo.toml').read_text())
        assert metadata['package']['version'] == '1.2.4'
        for dependency_name, dependency in metadata.get('dependencies', {}).items():
            if isinstance(dependency, dict) and dependency.get('package', dependency_name).startswith('invisi-sdk'):
                assert dependency['version'] == '=1.2.4' and 'path' not in dependency
        shutil.copytree(unpacked, destination)
        files = {str(p.relative_to(destination)): hashlib.sha256(p.read_bytes()).hexdigest() for p in destination.rglob('*') if p.is_file()}
        (destination / '.cargo-checksum.json').write_text(json.dumps({'files': files, 'package': None}))
        run(['cargo', '--config', config, 'test', '--locked', '--offline', '--all-features', '--manifest-path', unpacked / 'Cargo.toml'], cwd=work, env=environment)
    print(f'All seven 1.2.4 package archives verified and tested: {work}')


if __name__ == '__main__':
    main()
