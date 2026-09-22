"""Verify the documented fixtures, rule contract and pass/block outcomes offline."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import scan

ROOT = Path(__file__).resolve().parents[1]
CARD = ROOT / "examples" / "credit-card"


class CreditCardExampleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scan.yara.compile(filepath=str(CARD / "credit-card.yar"))

    def hits(self, text):
        return scan.detect(self.rules, text.encode())

    def test_positive_formats(self):
        for text in [
            'credit_card: 4242424242424242',
            'Credit Card Number: 4242 4242 4242 4242',
            'card-number = 4242-4242-4242-4242',
            '{"cardNumber": "4242424242424242"}',
            '  CREDIT_CARD = 4242424242424242  ',
        ]:
            with self.subTest(text=text):
                hits = self.hits(text)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]['severity'], 'HIGH')
                self.assertIsNone(hits[0]['suggested_classification'])
                self.assertEqual(hits[0]['evidence_lines'], [])

    def test_negative_formats(self):
        for text in [
            '4242424242424242',
            'order_id: 4242424242424242',
            'credit_card: **** **** **** 4242',
            'credit_card: 424242424242424',
            'credit_card: 42424242424242424',
            'credit_card: 4242 4242 4242 4242 4242',
            'credit_card: 4242X4242X4242X4242',
            'credit_card: 4242-4242 4242-4242',
            'credit_card: 4242424242424242suffix',
            'credit_card:\n4242424242424242',
            'not_credit_card: 4242424242424242',
        ]:
            with self.subTest(text=text):
                self.assertFalse(self.hits(text))

    def test_example_is_not_a_checksum_validator(self):
        self.assertEqual(len(self.hits('credit_card: 0000000000000001')), 1)

    def test_fixtures_and_occurrence_comparison(self):
        self.assertFalse(scan.detect(self.rules, (CARD / 'passing.txt').read_bytes()))
        text = (CARD / 'failing.txt').read_text()
        base = self.hits(text)
        self.assertEqual((len(base), base[0]['line']), (1, 2))
        self.assertEqual(scan.introduced(self.hits('\n' + text), base), [])
        head = self.hits(text + 'credit_card: 4242 4242 4242 4242\n')
        new = scan.introduced(head, base)
        self.assertEqual((len(new), new[0]['line']), (1, 3))

    def test_documented_fork_integration_survives_generation(self):
        # Follow the tutorial in an isolated copy, not the working rules tree.
        with tempfile.TemporaryDirectory() as temp:
            fork = Path(temp)
            shutil.copytree(ROOT / 'rules', fork / 'rules')
            (fork / 'tools').mkdir()
            (fork / 'rules' / 'custom').mkdir(exist_ok=True)
            shutil.copyfile(CARD / 'credit-card.yar', fork / 'rules/custom/credit-card.yar')
            generator = (ROOT / 'tools/build_rules.py').read_text()
            before = "'logic/dob-with-name','logic/sin-with-name'))"
            after = "'logic/dob-with-name','logic/sin-with-name','custom/credit-card'))"
            self.assertEqual(generator.count(before) + generator.count(after), 1)
            (fork / 'tools/build_rules.py').write_text(generator.replace(before, after))
            subprocess.run([sys.executable, str(fork / 'tools/build_rules.py')], check=True)
            for profile, count in [('code', 28), ('code-with-markings', 53)]:
                rules = scan.yara.compile(filepath=str(fork / 'rules/profiles' / (profile + '.yar')))
                self.assertEqual(len(list(rules)), count)
                hits = scan.detect(rules, (CARD / 'failing.txt').read_bytes())
                self.assertEqual([h['rule'] for h in hits], ['example_credit_card_number'])


class PipelineExamplesTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.repo = self.directory / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        # Don't append synthetic test results to the CI job's action outputs.
        self.enterContext(patch.dict(os.environ, {'GITHUB_OUTPUT': '', 'GITHUB_STEP_SUMMARY': ''}))

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL)

    def commit_fixture(self, fixture):
        shutil.copyfile(fixture, self.repo / 'record.txt')
        self.git('add', 'record.txt')
        self.git('-c', 'user.name=Scanner Demo', '-c', 'user.email=demo@example.invalid',
                 'commit', '-qm', 'Synthetic fixture')
        return self.git('rev-parse', 'HEAD').decode().strip()

    def run_scan(self, *extra):
        args = ['--repo', str(self.repo), '--mode', 'full', '--fail-on', 'HIGH',
                '--output', str(self.directory / 'reports'), *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = scan.main(args)
        report = json.loads((self.directory / 'reports/findings.json').read_text())
        self.assertFalse(report['errors'])
        return result, report

    def test_passing_pipeline_has_no_findings(self):
        self.commit_fixture(ROOT / 'examples/fixtures/passing.txt')
        status, report = self.run_scan()
        self.assertEqual(status, 0)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['coverage']['scanned_head'], 1)

    def test_failing_pipeline_is_a_finding_not_a_scanner_error(self):
        self.commit_fixture(ROOT / 'examples/fixtures/failing.txt')
        status, report = self.run_scan()
        self.assertEqual(status, 1)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['rule'], 'personal_sin_en')
        self.assertEqual(report['findings'][0]['severity'], 'HIGH')
        self.assertEqual(report['findings'][0]['line'], 3)
        self.assertEqual(report['coverage']['scanned_head'], 1)

    def test_report_only_passes_but_still_reports(self):
        self.commit_fixture(ROOT / 'examples/fixtures/failing.txt')
        status, report = self.run_scan('--fail-on', 'NONE')
        self.assertEqual((status, len(report['findings'])), (0, 1))

    def test_changes_mode_blocks_new_synthetic_data(self):
        base = self.commit_fixture(ROOT / 'examples/fixtures/passing.txt')
        self.commit_fixture(ROOT / 'examples/fixtures/failing.txt')
        status, report = self.run_scan('--mode', 'changes', '--base', base)
        self.assertEqual((status, len(report['findings'])), (1, 1))

    def test_credit_card_reports_do_not_expose_values(self):
        self.commit_fixture(CARD / 'failing.txt')
        rules = scan.yara.compile(filepath=str(CARD / 'credit-card.yar'))
        with patch.object(scan, 'compile_profile', return_value=rules):
            status, report = self.run_scan()
        self.assertEqual((status, len(report['findings'])), (1, 1))
        for path in (self.directory / 'reports').iterdir():
            text = path.read_text()
            self.assertNotIn('4242', text)
            self.assertNotIn('_signature', text)


if __name__ == '__main__':
    unittest.main()
