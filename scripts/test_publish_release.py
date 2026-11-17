"""Regression tests for release integrity, safe retries and cohort ordering."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import sys
from unittest.mock import patch
import urllib.error

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('publish_release', Path(__file__).with_name('publish-release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

spec = importlib.util.spec_from_file_location('check_release', Path(__file__).with_name('check-release.py'))
archive_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive_check)


class ReleaseTests(unittest.TestCase):
    def test_heavy_runtime_assets_are_external_even_when_authenticated(self):
        import hashlib
        artifact = 'circuits/provenance/k10/target/provenance_k10.json'
        vk = 'circuits/provenance/k10/target/evm/vk'
        payload = b'public runtime data'
        digest = hashlib.sha256(payload).hexdigest()
        manifest = {'circuits': [{'artifact': artifact, 'artifactSha256': digest, 'vk': vk, 'vkSha256': digest}]}
        base = {'provenance/manifest.json': json.dumps(manifest).encode(), 'provenance/' + artifact: payload, 'provenance/' + vk: payload}
        def verify(files, name='invisi-sdk-prover'):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as output:
                for path, data in dict(files, LICENSE=(archive_check.ROOT / 'LICENSE').read_bytes(), NOTICE=(archive_check.ROOT / 'NOTICE').read_bytes()).items():
                    member = tarfile.TarInfo(name + '-1.2.5/' + path)
                    member.size = len(data)
                    output.addfile(member, io.BytesIO(data))
            buffer.seek(0)
            with tarfile.open(fileobj=buffer) as contents:
                archive_check.check_archive_artifacts(contents, name)
        verify({'provenance/manifest.json': json.dumps(manifest).encode()})
        for files in [base, dict(base, **{'target/cache': payload}), dict(base, **{'provenance/' + artifact: b'tampered'}), {path: data for path, data in base.items() if path != 'provenance/' + vk}]:
            with self.assertRaises(RuntimeError):
                verify(files)
        with self.assertRaises(RuntimeError):
            verify(base, 'invisi-sdk')

    def cohort(self, root):
        import shutil
        (root / 'scripts').mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(__file__).with_name('release-notes.py'), root / 'scripts/release-notes.py')
        (root / 'CHANGELOG.md').write_text('# Changes\n## 1.2.0\n- Version details.\n')
        for name in release.ORDER:
            directory = root if name == 'invisi-sdk' else root / 'crates' / name
            directory.mkdir(parents=True, exist_ok=True)
            (directory / 'Cargo.toml').write_text(f'[package]\nname="{name}"\nversion="1.2.0"\nrepository="https://github.com/invisi-lab/invisi-sdk-rust"\n')

    def test_rejects_wrong_repository_tag_commit_dirty_and_cohort(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.cohort(root)
            with patch.object(release, 'git', side_effect=lambda root, *args: '' if args[0] == 'status' else 'a' * 40):
                for tag, repository in [('1.2.0', release.REPOSITORY), ('v1.2.0-rc.1', release.REPOSITORY), ('v1.2.1', release.REPOSITORY), ('v1.2.0', 'someone/fork')]:
                    with self.subTest(tag=tag, repository=repository), self.assertRaises(release.ReleaseError):
                        release.validate(root, tag, repository)
                self.assertEqual(release.validate(root, 'v1.2.0', release.REPOSITORY), ('1.2.0', 'a' * 40))
            with patch.object(release, 'git', side_effect=lambda root, *args: '' if args[0] == 'status' else ('a' * 40 if args[-1] == 'HEAD' else 'b' * 40)):
                with self.assertRaisesRegex(release.ReleaseError, 'tag'):
                    release.validate(root, 'v1.2.0', release.REPOSITORY)
            with patch.object(release, 'git', side_effect=lambda root, *args: ' M Cargo.toml' if args[0] == 'status' else 'a' * 40):
                with self.assertRaisesRegex(release.ReleaseError, 'clean'):
                    release.validate(root, 'v1.2.0', release.REPOSITORY)
            with patch.object(release, 'git', side_effect=lambda root, *args: '' if args[0] == 'status' else 'a' * 40):
                (root / 'crates/invisi-sdk-rpc/Cargo.toml').write_text('[package]\nname="invisi-sdk-rpc"\nversion="1.1.7"\n')
                with self.assertRaises(release.ReleaseError):
                    release.validate(root, 'v1.2.0', release.REPOSITORY)

    def test_rejects_missing_current_version_changelog(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.cohort(root)
            (root / 'CHANGELOG.md').write_text('# Changes\n## 1.1.7\n- Old details.\n')
            with patch.object(release, 'git', side_effect=lambda root, *args: '' if args[0] == 'status' else 'a' * 40):
                with self.assertRaisesRegex(release.ReleaseError, 'changelog'):
                    release.validate(root, 'v1.2.0', release.REPOSITORY)

    def test_archive_requires_tagged_clean_vcs_and_cohort_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'invisi-sdk-1.2.0.crate'
            def make(sha='a' * 40, dirty=False, version='1.2.0'):
                with tarfile.open(archive, 'w:gz') as output:
                    for name, data in {'.cargo_vcs_info.json': json.dumps({'git': {'sha1': sha, 'dirty': dirty}}), 'Cargo.toml': f'[package]\nname="invisi-sdk"\nversion="{version}"\n'}.items():
                        content = data.encode()
                        info = tarfile.TarInfo('invisi-sdk-1.2.0/' + name)
                        info.size = len(content)
                        output.addfile(info, io.BytesIO(content))
            make()
            self.assertEqual(len(release.archive_checksum(archive, 'invisi-sdk', '1.2.0', 'a' * 40)), 64)
            for values in [{'dirty': True}, {'sha': 'b' * 40}, {'version': '1.1.7'}]:
                make(**values)
                with self.assertRaises(release.ReleaseError):
                    release.archive_checksum(archive, 'invisi-sdk', '1.2.0', 'a' * 40)

    def test_existing_version_requires_exact_checksum_and_never_yanked(self):
        self.assertTrue(release.existing_matches({'checksum': 'abc', 'yanked': False}, 'abc'))
        self.assertFalse(release.existing_matches(None, 'abc'))
        for record in [{'checksum': 'foreign', 'yanked': False}, {'checksum': 'abc', 'yanked': True}]:
            with self.assertRaises(release.ReleaseError):
                release.existing_matches(record, 'abc')

    def test_http_429_retries_are_bounded_and_404_is_missing(self):
        error = urllib.error.HTTPError('https://example.invalid', 429, 'rate limited', {'Retry-After': '900'}, None)
        with patch.object(release.urllib.request, 'urlopen', side_effect=error), patch.object(release.time, 'sleep') as sleep:
            with self.assertRaises(release.ReleaseError):
                release.request_bytes('https://example.invalid', attempts=3)
            self.assertEqual(sleep.call_count, 2)
            self.assertTrue(all(call.args[0] <= 30 for call in sleep.call_args_list))
        missing = urllib.error.HTTPError('https://example.invalid', 404, 'missing', {}, None)
        with patch.object(release.urllib.request, 'urlopen', side_effect=missing):
            self.assertIsNone(release.request_bytes('https://example.invalid'))
        error.close()
        missing.close()

    def test_cohort_waits_before_next_package_and_resumes_exact_versions(self):
        calls = []
        class Registry:
            def version(self, name, version):
                return {'checksum': name, 'yanked': False} if name == release.ORDER[0] else None
            def wait(self, name, version, checksum):
                calls.append(('indexed', name))
        def package(root, name, version, commit, target):
            calls.append(('package', name))
            return name
        def command(args, **kwargs):
            self.assertNotIn('--no-verify', args)
            calls.append(('publish', args[-1]))
        with tempfile.TemporaryDirectory() as temporary, patch.object(release, 'package', side_effect=package), patch.object(release, 'run', side_effect=command), patch.object(release, 'archive_checksum', side_effect=lambda archive, name, version, commit: name):
            report = release.publish_cohort(Path(temporary), '1.2.0', 'a' * 40, Path(temporary), Registry())
        self.assertEqual(len(report['crates']), len(release.ORDER))
        self.assertNotIn(('publish', release.ORDER[0]), calls)
        self.assertEqual([name for operation, name in calls if operation == 'indexed'], release.ORDER)
        for current, following in zip(release.ORDER, release.ORDER[1:]):
            self.assertLess(calls.index(('indexed', current)), calls.index(('package', following)))

    def test_registry_wait_requires_api_index_and_download_agreement(self):
        payload = b'exact tagged crate'
        checksum = release.hashlib.sha256(payload).hexdigest()
        registry = release.Registry()
        index = json.dumps({'vers': '1.2.0', 'cksum': checksum, 'yanked': False}).encode()
        with patch.object(registry, 'version', return_value={'checksum': checksum, 'yanked': False}), patch.object(release, 'request_bytes', side_effect=[index, payload]):
            registry.wait('invisi-sdk', '1.2.0', checksum)
        for responses in [[index, b'foreign archive'], [json.dumps({'vers': '1.2.0', 'cksum': 'foreign', 'yanked': False}).encode()]]:
            with patch.object(registry, 'version', return_value={'checksum': checksum, 'yanked': False}), patch.object(release, 'request_bytes', side_effect=responses), self.assertRaises(release.ReleaseError):
                registry.wait('invisi-sdk', '1.2.0', checksum)
        with patch.object(registry, 'version', return_value=None) as version, patch.object(release.time, 'sleep'), self.assertRaisesRegex(release.ReleaseError, 'timed out'):
            registry.wait('invisi-sdk', '1.2.0', checksum)
        self.assertEqual(version.call_count, 12)

    def test_missing_secret_fails_before_any_publish(self):
        with patch.dict(release.os.environ, {}, clear=True), self.assertRaisesRegex(release.ReleaseError, 'CARGO_REGISTRY_TOKEN'):
            release.require_token()


if __name__ == '__main__':
    unittest.main()
