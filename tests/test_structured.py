"""Structured records, original locations and PR deltas; synthetic data only.

Run by the existing Test scanner workflow alongside the text-scanning tests.
"""
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import scan
import structured_data

EXAMPLES = scan.ROOT / 'examples' / 'structured'


class StructuredRulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = scan.compile_profile('code')

    def hits(self, text, suffix='json', rules=None):
        return scan.detect_file(rules or self.rules, text.encode(), 'data.' + suffix)

    def test_employee_fixtures_all_identifiers_and_locations(self):
        for suffix, lines, names in [
            ('xml', {'sin': 4, 'pri': 9, 'dob': 10}, {'sin': [3], 'pri': [7, 8], 'dob': [7, 8]}),
            ('json', {'sin': 6, 'pri': 11, 'dob': 12}, {'sin': [4, 5], 'pri': [9, 10], 'dob': [9, 10]}),
            ('yaml', {'sin': 5, 'pri': 8, 'dob': 9}, {'sin': [3, 4], 'pri': [6, 7], 'dob': [6, 7]}),
        ]:
            with self.subTest(suffix=suffix):
                hits = self.hits((EXAMPLES / ('employees.' + suffix)).read_text(), suffix)
                self.assertEqual(len(hits), 3)
                for hit in hits:
                    kind = hit['rule'].split('_')[1]
                    self.assertEqual(hit['line'], lines[kind])
                    self.assertEqual(hit['evidence_lines'], names[kind])
                    self.assertEqual(hit['severity'], 'HIGH' if kind == 'sin' else 'MEDIUM')
                    self.assertEqual(hit['suggested_classification'], 'Protected B' if kind == 'sin' else 'Protected A')

    def test_six_language_combinations(self):
        for suffix in ['json', 'yaml', 'xml']:
            for name_key, name, lang, labels in [
                ('name', 'Jane Example', 'en', ['pri', 'sin', 'dob']),
                ('nom', 'Élodie Exemple', 'fr', ['cidp', 'nas', 'ddn']),
            ]:
                for kind, label in zip(['pri', 'sin', 'dob'], labels):
                    value = '1987-03-21' if kind == 'dob' else '123456789'
                    data = {label: value, name_key: name}
                    text = (json.dumps(data) if suffix == 'json' else
                            '\n'.join(f'{k}: {v}' for k, v in data.items()) if suffix == 'yaml' else
                            '<person>' + ''.join(f'<{k}>{v}</{k}>' for k, v in data.items()) + '</person>')
                    with self.subTest(suffix=suffix, kind=kind, lang=lang):
                        self.assertEqual([h['rule'] for h in self.hits(text, suffix)], [f'personal_{kind}_{lang}'])

    def test_first_name_alone_and_schema_keys_do_not_match(self):
        for suffix, text in [
            ('xml', '<person><firstname>John</firstname><pri>12345678</pri></person>'),
            ('json', '{"firstname":"John","pri":"12345678"}'),
            ('yaml', 'firstname: John\npri: 12345678'),
            ('xml', '<person><firstname/><lastname/><pri/></person>'),
            ('json', '{"firstname":"string","lastname":"string","sin":"integer"}'),
        ]:
            with self.subTest(suffix=suffix, text=text):
                self.assertFalse(self.hits(text, suffix))

    def test_no_evidence_across_records_or_nested_objects(self):
        for suffix, text in [
            ('json', '[{"name":"Jane Example"},{"sin":"000000000"}]'),
            ('json', '{"person":{"name":"Jane Example"},"other":{"sin":"000000000"}}'),
            ('json', '{"sin":"000000000","person":{"name":"Jane Example"}}'),
            ('json', '[{"firstname":"Jane","sin":"000000000"},{"lastname":"Example"}]'),
            ('yaml', '- name: Jane Example\n- sin: 000000000'),
            ('yaml', 'name: Jane Example\n---\nsin: 000000000'),
            ('xml', '<people><person name="Jane Example"/><person><sin>000000000</sin></person></people>'),
            ('xml', '<people name="Jane Example"><person><sin>000000000</sin></person></people>'),
        ]:
            with self.subTest(suffix=suffix, text=text):
                self.assertFalse(self.hits(text, suffix))

    def test_xml_attributes_entities_namespaces_and_multiline_values(self):
        text = ('<x:person xmlns:x="urn:test"\n'
                '  name="Jane Ex&#97;mple"\n'
                '  sin="000000000">\n'
                '  <x:pri>\n'
                '    12345678\n'
                '  </x:pri>\n'
                '</x:person>')
        hits = {h['rule']: h for h in self.hits(text, 'xml')}
        self.assertEqual(set(hits), {'personal_pri_en', 'personal_sin_en'})
        self.assertEqual(hits['personal_pri_en']['line'], 5)
        self.assertEqual(hits['personal_sin_en']['line'], 3)
        self.assertTrue(all(h['evidence_lines'] == [2] for h in hits.values()))

    def test_json_decodes_escaped_labels_and_unicode_without_changing_lines(self):
        hits = self.hits('{\n  "\\u0073in": "000000000",\n  "name": "Jane Example",\n  "note": "\\ud83d\\ude00"\n}')
        self.assertEqual((len(hits), hits[0]['line'], hits[0]['evidence_lines']), (1, 2, [3]))

    def test_yaml_anchors_preserve_source_lines_and_zeroes(self):
        text = 'person: &person\n  name: Jane Example\n  sin: 000000000\ncopy: *person\n'
        hits = self.hits(text, 'yml')
        self.assertEqual(len(hits), 2)
        self.assertEqual([h['ordinal'] for h in hits], [1, 2])
        self.assertTrue(all(h['line'] == 3 and h['evidence_lines'] == [2] for h in hits))

    def test_generic_fields_use_existing_credit_card_example(self):
        rules = scan.yara.compile(filepath=str(scan.ROOT / 'examples/credit-card/credit-card.yar'))
        for suffix, text in [
            ('json', '{"credit_card":4242424242424242}'),
            ('yaml', 'credit_card: "4242424242424242"'),
            ('xml', '<payment><credit_card>4242424242424242</credit_card></payment>'),
        ]:
            with self.subTest(suffix=suffix):
                self.assertEqual([h['rule'] for h in self.hits(text, suffix, rules)], ['example_credit_card_number'])

    def test_protected_a_boolean_example_requires_true(self):
        rules = scan.yara.compile(filepath=str(EXAMPLES / 'protected-a.yar'))
        for suffix, text in [
            ('json', (EXAMPLES / 'flags.json').read_text()),
            ('yaml', '- "PROTECTED A": true\n- "PROTECTED A": false'),
            ('xml', '<flags><PROTECTED_A>true</PROTECTED_A><PROTECTED_A>false</PROTECTED_A></flags>'),
        ]:
            with self.subTest(suffix=suffix):
                self.assertEqual([h['rule'] for h in self.hits(text, suffix, rules)], ['example_protected_a_flag'])
        for value in ['false', 'null', '0', '"trueish"', '{"type":"boolean"}']:
            self.assertFalse(self.hits('{"PROTECTED A":' + value + '}', rules=rules))
        # This is an opt-in example, not a change to the bundled profile.
        self.assertFalse(self.hits('{"PROTECTED A":true}'))

    def test_formatting_order_and_duplicate_occurrences_in_changes_mode(self):
        record = {'name': 'Jane Example', 'sin': '000000000'}
        base = self.hits(json.dumps([record]))
        reordered = dict(reversed(list(record.items())))
        self.assertFalse(scan.introduced(self.hits(json.dumps([reordered], indent=2)), base))
        head = self.hits(json.dumps([record, record], indent=2))
        self.assertEqual(len(scan.introduced(head, base)), 1)
        self.assertEqual([h['ordinal'] for h in head], [1, 2])

    def test_plain_text_scanning_is_unchanged(self):
        text = b'SIN: 000000000\nName: Jane Example\n'
        self.assertEqual(scan.detect_file(self.rules, text, 'file.txt'), scan.detect(self.rules, text))

    def test_invalid_or_unsupported_structure_is_not_a_clean_scan(self):
        for suffix, text in [
            ('json', '{"sin": "sensitive-fragment",'),
            ('json', 'sin: 000000000\nname: Jane Example'),
            ('json', '{"name": NaN}'),
            ('yaml', 'name: [sensitive-fragment'),
            ('yaml', 'person: &person {child: *person}'),
            ('yaml', '? [complex, key]\n: value'),
            ('yaml', 'person: {<<: {name: Jane Example}}'),
            ('xml', '<person>sensitive-fragment'),
            ('xml', '<!DOCTYPE person [<!ENTITY x SYSTEM "file:///etc/passwd">]><person>&x;</person>'),
        ]:
            with self.subTest(suffix=suffix):
                with self.assertRaises(scan.ScanError) as raised:
                    self.hits(text, suffix)
                self.assertNotIn('sensitive-fragment', str(raised.exception))

    def test_yaml_tags_are_data_and_limits_reject_excessive_expansion(self):
        text = '!!python/object/apply:os.system ["must never execute"]'
        with patch.object(os, 'system', side_effect=AssertionError('executed')):
            self.assertFalse(self.hits(text, 'yaml'))
        with patch.object(structured_data, 'MAX_FIELD_CHARACTERS', 30):
            with self.assertRaises(scan.ScanError):
                self.hits('record: &a {field: "1234567890"}\ncopies: [*a, *a, *a]', 'yaml')
        with patch.object(structured_data, 'MAX_DEPTH', 3):
            for suffix, text in [('json', '[[[[0]]]]'), ('xml', '<a><b><c><d/></c></b></a>')]:
                with self.assertRaises(scan.ScanError):
                    self.hits(text, suffix)

    def test_timeout_applies_to_the_whole_structured_file(self):
        with patch.object(scan.time, 'monotonic', side_effect=[0, 11]):
            with self.assertRaises(scan.ScanError):
                self.hits('{"name":"Jane Example","sin":"000000000"}')


class StructuredPipelineTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Scanner Tests')
        self.git('config', 'user.email', 'test@example.invalid')
        self.enterContext(patch.dict(os.environ, {'GITHUB_OUTPUT': '', 'GITHUB_STEP_SUMMARY': ''}))

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL).decode().strip()

    def save(self, text, path='people.json'):
        (self.repo / path).write_text(text)
        self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic fixture')
        return self.git('rev-parse', 'HEAD')

    def run_scan(self, *extra):
        args = ['--repo', str(self.repo), '--mode', 'full', '--fail-on', 'HIGH',
                '--output', str(self.root / 'reports'), *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = scan.main(args)
        return status, json.loads((self.root / 'reports/findings.json').read_text())

    def test_full_and_pr_scans_redaction_source_locations_and_fingerprints(self):
        base = self.save('[{"sin":"000000000"}]')
        record = {'sin': '000000000', 'name': 'Jane Example'}
        self.save(json.dumps([record, record], indent=2))
        for extra in [(), ('--mode', 'changes', '--base', base)]:
            status, report = self.run_scan(*extra)
            self.assertEqual((status, len(report['findings'])), (1, 2))
            self.assertFalse(report['errors'])
            self.assertEqual([f['line'] for f in report['findings']], [3, 7])
            sarif = json.loads((self.root / 'reports/findings.sarif').read_text())
            results = sarif['runs'][0]['results']
            self.assertEqual(len({r['partialFingerprints']['rulePathOccurrence/v1'] for r in results}), 2)
            self.assertEqual([r['locations'][0]['physicalLocation']['region']['startLine'] for r in results], [3, 7])
            for output in (self.root / 'reports').iterdir():
                self.assertNotIn('000000000', output.read_text())
                self.assertNotIn('Jane Example', output.read_text())
                self.assertNotIn('_signature', output.read_text())

    def test_renaming_into_a_structured_format_is_scanned(self):
        text = '<person><sin>000000000</sin><name>Jane Example</name></person>'
        base = self.save(text, 'people.txt')
        (self.repo / 'people.txt').unlink()
        self.save(text, 'people.xml')
        status, report = self.run_scan('--mode', 'changes', '--base', base)
        self.assertEqual((status, len(report['findings'])), (1, 1))
        self.assertEqual(report['findings'][0]['path'], 'people.xml')

    def test_parse_failure_returns_two_and_redacts_error(self):
        self.save('{"name":"sensitive-fragment",')
        status, report = self.run_scan()
        self.assertEqual(status, 2)
        self.assertTrue(report['errors'])
        for output in (self.root / 'reports').iterdir():
            self.assertNotIn('sensitive-fragment', output.read_text())


if __name__ == '__main__':
    unittest.main()
