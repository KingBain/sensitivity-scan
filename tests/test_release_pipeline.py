"""Exercise the major-tag updater without making GitHub API calls."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TAG_SCRIPT = ROOT / "tools" / "sync_major_tag.sh"


class ReleaseTagTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.state = self.directory / "state.json"
        self.fake_gh = self.directory / "gh"
        self.fake_gh.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
state_file = pathlib.Path(os.environ['TEST_TAG_STATE'])
state = json.loads(state_file.read_text()) if state_file.exists() else {'refs': {}, 'writes': []}
args = sys.argv[1:]
method = next((a for a in args if a in ('GET','PATCH','POST')), 'GET')
path = next(a for a in args if a.startswith('repos/'))
if method == 'GET':
    sha = state['refs'].get(path)
    if not sha:
        sys.exit(1)
    print(sha)
else:
    fields = dict(args[i + 1].split('=', 1) for i, a in enumerate(args[:-1]) if a in ('-f', '-F'))
    if method == 'POST':
        key = 'repos/' + os.environ['GITHUB_REPOSITORY'] + '/git/' + fields['ref']
    else:
        key = path
    state['refs'][key] = fields['sha']
    state['writes'].append({'method': method, 'ref': key, 'sha': fields['sha']})
    state_file.write_text(json.dumps(state))
""")
        self.fake_gh.chmod(0o755)

    def run_tag(self, tag, sha):
        env = {**os.environ, "PATH": str(self.directory) + os.pathsep + os.environ["PATH"],
               "TEST_TAG_STATE": str(self.state), "GITHUB_REPOSITORY": "example/sensitivity-scan",
               "RELEASE_TAG": tag, "RELEASE_SHA": sha}
        return subprocess.run(["bash", str(TAG_SCRIPT)], env=env, capture_output=True, text=True)

    def test_creates_and_moves_major_tag(self):
        one = "a" * 40
        two = "b" * 40
        self.assertEqual(self.run_tag("v1.0.0", one).returncode, 0)
        self.assertEqual(self.run_tag("v1.0.1", two).returncode, 0)
        self.assertEqual(self.run_tag("v1.0.1", two).returncode, 0)
        state = json.loads(self.state.read_text())
        key = "repos/example/sensitivity-scan/git/refs/tags/v1"
        self.assertEqual(state["refs"][key], two)
        self.assertEqual([w["method"] for w in state["writes"]], ["POST", "PATCH"])

    def test_rejects_invalid_release_identifiers(self):
        for tag, sha in [("v1.0.0;bad", "a" * 40), ("v1.0.0", "not-a-sha"),
                         ("v1.2.0-rc.1", "a" * 40)]:
            with self.subTest(tag=tag):
                self.assertEqual(self.run_tag(tag, sha).returncode, 2)
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
