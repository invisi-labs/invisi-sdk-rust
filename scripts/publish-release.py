#!/usr/bin/env python3
"""Publish the eight tagged crates, resuming only byte-identical registered versions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.request

REPOSITORY = 'invisi-lab/invisi-sdk-rust'
ORDER = ['invisi-sdk-primitives', 'invisi-sdk-protocol', 'invisi-sdk-prover', 'invisi-sdk-rpc', 'invisi-sdk', 'invisi-sdk-session', 'invisi-sdk-ffi', 'invisi-sdk-ipp']


class ReleaseError(RuntimeError):
    pass


def run(args, **kwargs):
    print('+', ' '.join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()


def validate(root, tag, repository):
    if repository != REPOSITORY:
        raise ReleaseError(f'Release repository must be {REPOSITORY}')
    match = re.fullmatch(r'v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', tag)
    if not match:
        raise ReleaseError('Release tag must be a stable vMAJOR.MINOR.PATCH version')
    version = tag[1:]
    commit = git(root, 'rev-parse', 'HEAD')
    tagged = git(root, 'rev-parse', f'refs/tags/{tag}^{{commit}}')
    if tagged != commit:
        raise ReleaseError('Checked-out commit does not match the release tag')
    if git(root, 'status', '--porcelain', '--untracked-files=normal'):
        raise ReleaseError('Release checkout must be clean')
    found = set()
    for manifest in [root / 'Cargo.toml', *sorted((root / 'crates').glob('*/Cargo.toml'))]:
        data = tomllib.loads(manifest.read_text())
        package_data = data['package']
        name = package_data['name']
        if name not in ORDER or name in found or package_data['version'] != version:
            raise ReleaseError(f'Invalid eight-crate version cohort: {manifest}')
        if package_data.get('repository') != f'https://github.com/{REPOSITORY}':
            raise ReleaseError(f'Unexpected package repository: {name}')
        found.add(name)
        for table in ['dependencies', 'dev-dependencies', 'build-dependencies']:
            for dependency, settings in data.get(table, {}).items():
                canonical = settings.get('package', dependency) if isinstance(settings, dict) else dependency
                if canonical.startswith('invisi-sdk'):
                    if canonical not in ORDER or not isinstance(settings, dict) or settings.get('version') != f'={version}':
                        raise ReleaseError(f'Invalid sibling version requirement: {name}/{dependency}')
    if found != set(ORDER):
        raise ReleaseError('Release must contain exactly the eight public crates')
    try:
        run([sys.executable, root / 'scripts/release-notes.py', tag], stdout=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReleaseError('Release changelog is missing or invalid') from error
    return version, commit


def require_token():
    if not os.environ.get('CARGO_REGISTRY_TOKEN', '').strip():
        raise ReleaseError('CARGO_REGISTRY_TOKEN GitHub Actions repository secret is missing; configure it in repository Settings > Secrets and variables > Actions')


def request_bytes(url, attempts=6):
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'invisi-sdk-release/1.2.5 (+https://github.com/invisi-lab/invisi-sdk-rust)'})
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 404:
                return None
            if error.code != 429 and not 500 <= error.code < 600:
                raise ReleaseError(f'Registry HTTP {error.code}: {url}') from error
            try:
                delay = float(error.headers.get('Retry-After', 2 ** attempt))
            except (ValueError, TypeError):
                delay = 2 ** attempt
        except (urllib.error.URLError, TimeoutError):
            delay = 2 ** attempt
        if attempt + 1 == attempts:
            raise ReleaseError(f'Registry retry limit reached: {url}')
        time.sleep(min(30, max(1, delay)))
    raise ReleaseError('Registry request exhausted')


def existing_matches(record, checksum):
    if record is None:
        return False
    if record.get('yanked') or record.get('checksum') != checksum:
        raise ReleaseError('Existing immutable registry version differs from the exact tagged archive or is yanked; refusing to publish or skip')
    return True


class Registry:
    def version(self, name, version):
        content = request_bytes(f'https://crates.io/api/v1/crates/{name}/{version}')
        return json.loads(content)['version'] if content is not None else None

    def wait(self, name, version, checksum):
        for attempt in range(12):
            record = self.version(name, version)
            if record is not None:
                existing_matches(record, checksum)
                content = request_bytes(f'https://index.crates.io/{name[:2]}/{name[2:4]}/{name}')
                rows = [json.loads(line) for line in content.splitlines()] if content else []
                indexed = next((row for row in rows if row['vers'] == version), None)
                if indexed is not None:
                    if indexed.get('yanked') or indexed['cksum'] != checksum:
                        raise ReleaseError(f'Sparse-index checksum/yank mismatch: {name}')
                    archive = request_bytes(f'https://static.crates.io/crates/{name}/{name}-{version}.crate')
                    if archive is not None:
                        if hashlib.sha256(archive).hexdigest() != checksum:
                            raise ReleaseError(f'Downloaded archive checksum mismatch: {name}')
                        print(f'Verified registry, sparse index and archive: {name}@{version}', flush=True)
                        return
            if attempt < 11:
                time.sleep(10)
        raise ReleaseError(f'Registry propagation timed out: {name}@{version}; rerun the same tag after indexing')


def archive_checksum(archive, name, version, commit):
    prefix = f'{name}-{version}/'
    with tarfile.open(archive) as contents:
        def read(relative):
            item = contents.extractfile(prefix + relative)
            if item is None:
                raise ReleaseError(f'Missing archive metadata: {relative}')
            return item.read()
        info = json.loads(read('.cargo_vcs_info.json'))
        metadata = tomllib.loads(read('Cargo.toml').decode())['package']
        if info.get('git', {}).get('sha1') != commit or info['git'].get('dirty', False):
            raise ReleaseError(f'Archive was not built from the clean tagged commit: {name}')
        if metadata.get('name') != name or metadata.get('version') != version:
            raise ReleaseError(f'Archive cohort mismatch: {name}')
    return hashlib.sha256(archive.read_bytes()).hexdigest()


def package(root, name, version, commit, target):
    environment = os.environ.copy()
    environment['CARGO_TARGET_DIR'] = str(target)
    run(['cargo', 'package', '--locked', '--package', name], cwd=root, env=environment)
    return archive_checksum(target / 'package' / f'{name}-{version}.crate', name, version, commit)


def publish_cohort(root, version, commit, target, registry):
    report = {'version': version, 'commit': commit, 'crates': []}
    environment = os.environ.copy()
    environment['CARGO_TARGET_DIR'] = str(target)
    for name in ORDER:
        checksum = package(root, name, version, commit, target)
        exists = existing_matches(registry.version(name, version), checksum)
        if not exists:
            run(['cargo', 'publish', '--locked', '--package', name], cwd=root, env=environment)
            actual = archive_checksum(target / 'package' / f'{name}-{version}.crate', name, version, commit)
            if actual != checksum:
                raise ReleaseError(f'Cargo publish regenerated a different archive: {name}')
        registry.wait(name, version, checksum)
        report['crates'].append({'name': name, 'version': version, 'sha256': checksum, 'alreadyPublished': exists, 'url': f'https://crates.io/crates/{name}/{version}'})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', ''))
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--target-dir', type=Path)
    parser.add_argument('--report', type=Path)
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version, commit = validate(root, options.tag, options.repository)
    print(f'Validated {options.tag}: eight crates at clean commit {commit}', flush=True)
    if options.validate_only:
        return
    require_token()
    if options.target_dir is None or options.report is None:
        raise ReleaseError('--target-dir and --report are required for publishing')
    report = publish_cohort(root, version, commit, options.target_dir.resolve(), Registry())
    options.report.parent.mkdir(parents=True, exist_ok=True)
    options.report.write_text(json.dumps(report, indent=2) + '\n')
    print('All eight registry archives match the tagged release', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ReleaseError, subprocess.CalledProcessError, KeyError) as error:
        print(f'Release failed: {error}', file=sys.stderr)
        sys.exit(1)
