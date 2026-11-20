"""Split resource tooling must preserve immutable historical trust anchors."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
class LegacyPinTests(unittest.TestCase):
    def test_update_pin_cannot_replace_a_legacy_snapshot(self):
        for selected,filename in [('legacy','legacy-resource-release.json'),('legacy-initial-payment','initial-payment-resource-release.json')]:
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                (root/'scripts').mkdir();pins=root/'crates/invisi-sdk-prover/assets/prover';pins.mkdir(parents=True)
                shutil.copyfile(ROOT/'scripts/sync-prover-assets.py',root/'scripts/sync-prover-assets.py')
                original=(ROOT/'crates/invisi-sdk-prover/assets/prover'/filename).read_bytes();(pins/filename).write_bytes(original)
                source=root/'source';source.mkdir();data=b'{}';digest=hashlib.sha256(data).hexdigest()
                index={'format':'invisi.prover-assets.v1','noirVersion':'1.0.0','bbVersion':'6.0.0','files':{'circuits/example.json':{'sha256':digest,'size':len(data)}}}
                (source/'index.json').write_text(json.dumps(index));(source/(digest+'.json')).write_bytes(data)
                result=subprocess.run([sys.executable,str(root/'scripts/sync-prover-assets.py'),str(source),'--set',selected,'--update-pin'],capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual((pins/filename).read_bytes(),original)
if __name__=='__main__':unittest.main()
