"""Synthetic fixtures only. Tests do not require network access or GitHub credentials."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import scan


class RulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scan.compile_profile("code")

    def hits(self, text):
        return scan.detect(self.rules, text.encode())

    def test_counts(self):
        core = list(self.rules)
        self.assertEqual(len(core), 27)
        self.assertEqual(sum(not r.is_private for r in core), 6)
        self.assertEqual(len(list(scan.compile_profile("code-with-markings"))), 52)

    def test_six_combinations(self):
        for lang, name in [("en", 'Full Name: Jane Example'), ("fr", 'Nom: Élodie Exemple')]:
            for kind, field in [("pri", "PRI" if lang == "en" else "CIDP"),
                                ("sin", "SIN" if lang == "en" else "NAS"),
                                ("dob", "DOB" if lang == "en" else "DDN")]:
                value = '1987-03-21' if kind == 'dob' else '123-456-789'
                with self.subTest(lang=lang, kind=kind):
                    hits = self.hits(f'{field}: {value}\n{name}\n')
                    self.assertEqual([h['rule'] for h in hits], [f'personal_{kind}_{lang}'])
                    self.assertEqual(hits[0]['suggested_classification'], 'Protected B' if kind == 'sin' else 'Protected A')

    def test_long_labels(self):
        samples = [('personalRecordIdentifier', 'Jane Example', 'Full Name'),
                   ('Social_Insurance_Number', 'Jane Example', 'name'),
                   ("Code d’identification de dossier personnel", 'Élodie Exemple', 'nom'),
                   ("Numéro d’assurance sociale", 'Élodie Exemple', 'nom')]
        for label, name, key in samples:
            with self.subTest(label=label):
                self.assertTrue(self.hits(f'{label}: 123456789\n{key}: {name}'))

    def test_split_name_json(self):
        hits = self.hits('{"sin": "123456789", "first_name": "Jane", "lastName": "Example"}')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['line'], 1)

    def test_accented_name(self):
        hits = self.hits('NAS: 123456789\nPrénom: André\nNom de famille: Noël')
        self.assertEqual(hits[0]['evidence_lines'], [2, 3])

    def test_no_false_full_name_from_french_label(self):
        self.assertFalse(self.hits('NAS: 123456789\nNom de famille: Martin'))
        self.assertFalse(self.hits('NAS: 123456789\nNom de famille:'))

    def test_no_bare_values_or_schema_labels(self):
        for text in ['123456789\nName: Jane Example', 'SIN: 123456789',
                     'SIN: int\nFirst Name: string\nLast Name: string',
                     'SIN: 123456789\nFirst Name:\nLast Name:',
                     'SIN: 123456789\nName: Jane', 'SIN: 123456789\nFirst Name: Jane']:
            with self.subTest(text=text):
                self.assertFalse(self.hits(text))

    def test_reject_malformed_identifiers(self):
        for value in ['123X456Y789', '1234567890', '12345678', 'abc']:
            self.assertFalse(self.hits(f'SIN: {value}\nName: Jane Example'))

    def test_line_locations_and_no_cross_line_name(self):
        hit = self.hits('\nSIN: 123456789\n\nFirst Name: Jane\nLast Name: Example')[0]
        self.assertEqual((hit['line'], hit['evidence_lines']), (2, [4, 5]))
        self.assertFalse(self.hits('SIN: 123456789\nName: Jane\nExample'))

    def test_second_identifier_same_file(self):
        base = self.hits('Name: Jane Example\nSIN: 123456789\n')
        head = self.hits('Name: Jane Example\nSIN: 123456789\nSIN: 987654321\n')
        new = scan.introduced(head, base)
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]['line'], 3)

    def test_duplicate_occurrence_and_line_shifts(self):
        text = 'Name: Jane Example\nSIN: 123456789\n'
        self.assertEqual(scan.introduced(self.hits('\n\n'+text), self.hits(text)), [])
        self.assertEqual(len(scan.introduced(self.hits(text+'SIN: 123456789\n'), self.hits(text))), 1)

    def test_changed_supporting_name(self):
        base = self.hits('Name: Jane Example\nSIN: 123456789')
        head = self.hits('Name: Alice Example\nSIN: 123456789')
        self.assertEqual(len(scan.introduced(head, base)), 1)

    def test_optional_markings_and_no_form_rules(self):
        text = 'NATO RESTRICTED\nNATO UNCLASSIFIED\nOATH OR SOLEMN AFFIRMATION\nWHMIS INVENTORY'
        self.assertFalse(self.hits(text))
        self.assertEqual(len(scan.detect(scan.compile_profile('code-with-markings'), text.encode())), 2)
        for rule in scan.compile_profile('code-with-markings'):
            self.assertNotIn('form_', rule.identifier)
            self.assertNotIn('ssc', rule.identifier.lower())

    def test_timeout_is_not_clean_scan(self):
        rules = unittest.mock.Mock()
        rules.match.side_effect = scan.yara.TimeoutError('test')
        with self.assertRaises(scan.yara.TimeoutError):
            scan.detect(rules, b'test')

    def test_match_warning_is_error(self):
        class Limited:
            def match(self, **kwargs):
                kwargs['warnings_callback'](1, None)
                return []
        with self.assertRaises(scan.ScanError):
            scan.detect(Limited(), b'test')


class GitTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Scanner Tests')
        self.write('README.md', 'Synthetic test repository\n')
        self.base = self.save()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL).decode().strip()

    def write(self, path, text):
        p = self.repo / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def save(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def options(self, **kwargs):
        default = dict(repo=self.repo, profile='code', mode='full', base='', head='', exclusions='[]',
                       max_file_bytes=2097152, timeout=10)
        default.update(kwargs)
        return argparse.Namespace(**default)

    def test_committed_only_and_no_execution(self):
        self.write('record.txt', 'SIN: 123456789\nName: Jane Example')
        self.write('sitecustomize.py', 'raise RuntimeError("must never run")')
        self.save()
        self.write('untracked.txt', 'SIN: 987654321\nName: Alice Example')
        self.write('record.txt', 'changed but uncommitted')
        report = scan.scan(self.options())
        self.assertEqual([f['path'] for f in report['findings']], ['record.txt'])

    def test_base_comparison_complete_files(self):
        self.write('data.txt', 'Name: Jane Example\nSIN: 123456789\n')
        base = self.save()
        self.write('data.txt', 'Name: Jane Example\nSIN: 123456789\nSIN: 987654321\n')
        self.save()
        report = scan.scan(self.options(mode='changes', base=base))
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['line'], 3)
        self.assertEqual(report['coverage']['scanned_base'], 1)

    def test_new_name_activates_existing_identifier(self):
        self.write('data.txt', 'SIN: 123456789\n')
        base = self.save()
        self.write('data.txt', 'SIN: 123456789\nName: Jane Example\n')
        self.save()
        self.assertEqual(len(scan.scan(self.options(mode='changes', base=base))['findings']), 1)

    def test_exact_rename_and_delete(self):
        self.write('old.txt', 'SIN: 123456789\nName: Jane Example')
        base = self.save()
        (self.repo/'old.txt').rename(self.repo/'new.txt')
        self.save()
        self.assertFalse(scan.scan(self.options(mode='changes', base=base))['findings'])
        (self.repo/'new.txt').unlink()
        self.save()
        self.assertFalse(scan.scan(self.options(mode='changes', base=base))['findings'])

    def test_skips_are_reported_and_workflow_files_scanned(self):
        (self.repo/'binary.bin').write_bytes(b'\x00SIN: 123456789')
        (self.repo/'latin.txt').write_bytes(b'\xff')
        (self.repo/'linked').symlink_to('README.md')
        self.write('large.txt', 'x'*512)
        self.write('lfs.txt', 'version https://git-lfs.github.com/spec/v1\noid sha256:abc\n')
        self.write('.github/fixture.yml', 'SIN: 123456789\nName: Jane Example')
        self.save()
        report = scan.scan(self.options(max_file_bytes=200))
        self.assertEqual({s['reason'] for s in report['coverage']['skipped']},
                         {'binary_or_utf16','non_utf8','symlink_or_submodule','size_limit','git_lfs_pointer'})
        self.assertEqual(report['findings'][0]['path'], '.github/fixture.yml')

    def test_exclusions_require_reasons(self):
        self.write('sample.txt', 'SIN: 123456789\nName: Jane Example')
        self.save()
        with self.assertRaises(scan.ScanError):
            scan.scan(self.options(exclusions='[{"glob":"*"}]'))
        result = scan.scan(self.options(exclusions='[{"glob":"sample.txt","reason":"Synthetic fixture"}]'))
        self.assertFalse(result['findings'])
        self.assertEqual(result['coverage']['skipped'][0]['reason'], 'excluded: Synthetic fixture')

    def test_reports_omit_values_and_escape_paths(self):
        path = 'odd # name; $(echo bad).txt'
        self.write(path, '\nSIN: 123456789\nName: Jane Example')
        self.save()
        report = scan.scan(self.options())
        out = self.root / 'reports'
        scan.write_reports(report, out)
        for p in out.iterdir():
            text = p.read_text()
            self.assertNotIn('123456789', text)
            self.assertNotIn('Jane Example', text)
            self.assertNotIn('_signature', text)
        sarif = json.loads((out/'findings.sarif').read_text())
        self.assertEqual(report['version'], (scan.ROOT/'version.txt').read_text().strip())
        self.assertEqual(sarif['runs'][0]['tool']['driver']['version'], report['version'])
        result = sarif['runs'][0]['results'][0]
        self.assertEqual(result['locations'][0]['physicalLocation']['region']['startLine'], 2)
        self.assertIn('%23',result['locations'][0]['physicalLocation']['artifactLocation']['uri'])

    def test_cli_exit_codes_and_failed_report(self):
        self.write('sample.txt', 'SIN: 123456789\nName: Jane Example')
        self.save()
        args = ['--repo', str(self.repo), '--mode', 'full', '--output', str(self.root/'output')]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scan.main(args), 0)
            self.assertEqual(scan.main(args+['--fail-on','HIGH']), 1)
            self.assertEqual(scan.main(args+['--head','nonexistent']), 2)
        report = json.loads((self.root/'output/findings.json').read_text())
        self.assertTrue(report['errors'])

    def test_pull_request_event_auto_mode(self):
        self.write('new.txt', 'SIN: 123456789\nName: Jane Example')
        head = self.save()
        event = self.root/'event.json'
        event.write_text(json.dumps({'pull_request': {'base': {'sha': self.base}, 'head': {'sha': head}}}))
        with patch.dict(os.environ, {'GITHUB_EVENT_NAME':'pull_request', 'GITHUB_EVENT_PATH':str(event)}):
            report = scan.scan(self.options(mode='auto'))
        self.assertEqual(report['mode'], 'changes')
        self.assertEqual(len(report['findings']), 1)


if __name__ == '__main__':
    unittest.main()
