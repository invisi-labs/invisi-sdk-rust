#!/usr/bin/env python3
"""Producer regression tests use the same public binary VKs as runtime tests."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sync_recursive_keys', ROOT / 'scripts/sync-recursive-keys.py')

class RecursiveKeySyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.metadata = json.loads((ROOT / 'crates/invisi-sdk-prover/assets/prover/recursive-key.json').read_text())
        self.catalog = json.loads((ROOT / 'crates/invisi-sdk-protocol/assets/circuit-statements.json').read_text())
        self.manifest = {'complete': True, 'bbVersion': '6.0.0', 'entries': []}
        for capacity in range(1, 11):
            name = f'transact_user_slots{capacity}'
            binary = (ROOT / f'crates/invisi-sdk-prover/assets/prover/testdata/recursive/{name}.vk').read_bytes()
            exported = {'bb_version': '6.0.0', 'scheme': 'ultra_honk', 'vk': ['0x' + binary[i:i+32].hex() for i in range(0, len(binary), 32)], 'hash': self.metadata[str(capacity)]['keyHash']}
            raw = json.dumps(exported).encode()
            (self.root / f'{name}.vk').write_bytes(binary)
            (self.root / f'{name}.json').write_bytes(raw)
            self.manifest['entries'].append({'name': name, 'recursive': {'target': 'noir-recursive', 'vk': f'{name}.vk', 'vkJson': f'{name}.json', 'vkSha256': hashlib.sha256(binary).hexdigest(), 'vkJsonSha256': hashlib.sha256(raw).hexdigest(), 'innerVkCommitment': self.metadata[str(capacity)]['innerVkCommitment']}})
        self.module = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(self.module)

    def generate(self):
        return self.module.authenticate_metadata(self.root, self.manifest, self.metadata, self.catalog)

    def test_emits_only_authenticated_small_metadata(self):
        expected = {k: {field: value[field] for field in ('keyHash', 'innerVkCommitment')} for k, value in self.metadata.items()}
        self.assertEqual(self.generate(), expected)

    def test_rejects_symlink_escape_from_export_root(self):
        target = ROOT / 'crates/invisi-sdk-prover/assets/prover/testdata/recursive/transact_user_slots1.vk'
        (self.root / 'escape.vk').symlink_to(target)
        with self.assertRaises(ValueError):
            self.module.read_export(self.root, 'escape.vk')

    def test_rejects_corrupt_json_binary_and_metadata(self):
        for which in ('json', 'binary', 'hash', 'commitment', 'width', 'noncanonical'):
            with self.subTest(which=which):
                entry = self.manifest['entries'][0]['recursive']
                path = self.root / entry['vkJson']
                original = path.read_bytes()
                binary_path = self.root / entry['vk']
                binary = binary_path.read_bytes()
                saved = copy.deepcopy(entry)
                if which == 'json': path.write_bytes(b'{}')
                elif which == 'binary': binary_path.write_bytes(bytes(len(binary)))
                elif which == 'commitment': entry['innerVkCommitment'] = '0x' + '00' * 32
                else:
                    data = json.loads(original)
                    if which == 'hash': data['hash'] = '0x' + '00' * 32
                    elif which == 'width': data['vk'].pop()
                    else: data['vk'][0] = '0x' + 'ff' * 32
                    raw = json.dumps(data).encode()
                    path.write_bytes(raw)
                    entry['vkJsonSha256'] = hashlib.sha256(raw).hexdigest()
                with self.assertRaises(ValueError): self.generate()
                path.write_bytes(original)
                binary_path.write_bytes(binary)
                entry.clear(); entry.update(saved)

if __name__ == '__main__': unittest.main()
