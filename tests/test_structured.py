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
import field_syntax

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

    def test_filename_does_not_select_matching_behavior(self):
        text = '<person><name>Jane Example</name><sin>000000000</sin></person>'
        expected = scan.detect_file(self.rules, text.encode(), 'data.xml')
        for path in ['source.cs', 'source.py', 'source.ts', 'source.rb', 'data.csv', 'data.unknown', 'Makefile']:
            with self.subTest(path=path):
                self.assertEqual(scan.detect_file(self.rules, text.encode(), path), expected)

    def test_common_field_syntax_inside_code(self):
        for text in [
            'const person = { first_name: "Jane", last_name: "Example", sin: "000000000" };',
            "person = {'name': 'Jane Example', 'sin': '000000000'}",
            'var person = new Person { Name = "Jane Example", SIN = "000000000" };',
            'person(name="Jane Example", sin="000000000")',
            "person = { 'name' => 'Jane Example', 'sin' => '000000000' }",
            'const name = "Jane Example"; const sin = "000000000";',
            'person.name = "Jane Example"; person.sin = "000000000";',
            'person["name"] = "Jane Example"; person["sin"] = "000000000";',
            'Name: Jane Example\nSIN 000000000',
        ]:
            with self.subTest(text=text):
                self.assertEqual([h['rule'] for h in self.hits(text, 'unknown')], ['personal_sin_en'])

    def test_separate_code_objects_do_not_share_names(self):
        for text in [
            'const a = {name: "Jane Example"}; const b = {sin: "000000000"};',
            'one(name="Jane Example"); two(sin="000000000")',
            'alice.name = "Jane Example"; bob.sin = "000000000";',
            'alice["name"] = "Jane Example"; bob["sin"] = "000000000";',
            'var a = new Person { Name = "Jane Example" }; var b = new Person { SIN = "000000000" };',
        ]:
            self.assertFalse(self.hits(text, 'unknown'))

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
        # The minimal code profile remains limited to identifiers with names.
        self.assertFalse(self.hits('{"PROTECTED A":true}'))

    def test_all_gc_classification_flags_in_markings_profile(self):
        rules = scan.compile_profile('code-with-markings')
        labels = [
            ('Protected', 'Protégé', 'LOW'),
            ('Protected A', 'Protégé A', 'MEDIUM'),
            ('Protected B', 'Protégé B', 'HIGH'),
            ('Protected C', 'Protégé C', 'CRITICAL'),
            ('Classified', 'Classifié', 'LOW'),
            ('Confidential', 'Confidentiel', 'MEDIUM'),
            ('Secret', 'Secret', 'HIGH'),
            ('Top Secret', 'Très secret', 'CRITICAL'),
            ('Unclassified', 'Non classifié', 'LOW'),
            ('Protected when Completed', 'Protégé lorsque rempli', 'LOW'),
        ]
        for english, french, severity in labels:
            for label in set([english, french]):
                xml_key = label.replace(' ', '_')
                for suffix, text in [
                    ('json', json.dumps({label: True})),
                    ('yaml', f'"{label}": true'),
                    ('xml', f'<flags><{xml_key}>true</{xml_key}></flags>'),
                ]:
                    with self.subTest(suffix=suffix, label=label):
                        hits = self.hits(text, suffix, rules)
                        self.assertEqual(len(hits), 1)
                        self.assertEqual(hits[0]['severity'], severity)
                        self.assertEqual(hits[0]['suggested_classification'], english)
                        self.assertTrue(hits[0]['rule'].startswith('flag_'))
                        self.assertFalse(self.hits(text.replace('true', 'false'), suffix, rules))
                for value in [False, None, '', 0, 'trueish']:
                    self.assertFalse(self.hits(json.dumps({label: value}), rules=rules))

    def test_existing_marking_flags_true_false_and_source_lines(self):
        rules = scan.compile_profile('code-with-markings')
        for label in ['NATO RESTRICTED', 'OTAN DIFFUSION RESTREINTE',
                      'NATO UNCLASSIFIED', 'OTAN NON-CLASSIFIÉ', 'UK OFFICIAL', 'RU OFFICIEL']:
            for suffix, positive, negative in [
                ('json', json.dumps({label: True}), json.dumps({label: False})),
                ('yaml', f'"{label}": true', f'"{label}": false'),
                ('xml', f'<record {label.replace(" ", "_")}="true"/>',
                        f'<record {label.replace(" ", "_")}="false"/>'),
            ]:
                with self.subTest(label=label, suffix=suffix):
                    self.assertEqual(len(self.hits(positive, suffix, rules)), 1)
                    self.assertFalse(self.hits(negative, suffix, rules))
            self.assertFalse(self.hits(json.dumps({label: None}), rules=rules))
        text = '{\n  "NATO RESTRICTED": false,\n  "UK OFFICIAL": true\n}'
        hits = self.hits(text, rules=rules)
        self.assertEqual([(h['rule'], h['line']) for h in hits], [('marking_uk_official_en', 3)])
        # Plain markings in values and unstructured text still work.
        self.assertEqual(len(self.hits('{"classification":"NATO RESTRICTED"}', rules=rules)), 1)
        self.assertEqual(len(self.hits('NATO RESTRICTED', 'txt', rules)), 1)

    def test_boolean_flags_do_not_replace_identifier_or_name_values(self):
        for field in ['sin', 'pri', 'dob']:
            self.assertFalse(self.hits(json.dumps({field: True, 'name': 'Jane Example'})))
        self.assertFalse(self.hits('{"sin":"000000000","firstname":true,"lastname":true}'))
        self.assertFalse(self.hits('{"sin":"000000000","name":true}'))

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
        def public(findings):
            return [{k: v for k, v in f.items() if k != '_signature'} for f in findings]
        self.assertEqual(public(scan.detect_file(self.rules, text, 'file.txt')), public(scan.detect(self.rules, text)))

    def test_snippets_do_not_need_to_be_valid_documents(self):
        for text in ['{sin: "000000000", name: "Jane Example",',
                     'sin: 000000000\nname: Jane Example',
                     '<sin>000000000</sin><name>Jane Example</name>']:
            # Deliberately not valid JSON, despite the filename.
            self.assertEqual(len(self.hits(text, 'json')), 1)

    def test_content_is_not_executed_and_limits_are_reported(self):
        text = '!!python/object/apply:os.system ["must never execute"]'
        with patch.object(os, 'system', side_effect=AssertionError('executed')):
            self.assertFalse(self.hits(text, 'yaml'))
        with patch.object(field_syntax, 'MAX_FIELD_CHARACTERS', 10):
            with self.assertRaises(scan.ScanError):
                self.hits('name: sensitive-fragment')
        with patch.object(field_syntax, 'MAX_DEPTH', 3):
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

    def test_changing_an_extension_does_not_change_the_scan(self):
        text = '<person><sin>000000000</sin><name>Jane Example</name></person>'
        base = self.save(text, 'people.txt')
        (self.repo / 'people.txt').unlink()
        self.save(text, 'people.xml')
        status, report = self.run_scan('--mode', 'changes', '--base', base)
        self.assertEqual((status, len(report['findings'])), (0, 0))

    def test_extraction_limit_returns_two_and_redacts_error(self):
        self.save('{"name":"sensitive-fragment",')
        with patch.object(field_syntax, 'MAX_FIELD_CHARACTERS', 10):
            status, report = self.run_scan()
        self.assertEqual(status, 2)
        self.assertTrue(report['errors'])
        for output in (self.root / 'reports').iterdir():
            self.assertNotIn('sensitive-fragment', output.read_text())

    def test_enabling_a_classification_flag_blocks_the_pr(self):
        base = self.save('[{"PROTECTED B":false}]')
        status, report = self.run_scan('--profile', 'code-with-markings')
        self.assertEqual((status, report['findings']), (0, []))
        self.save('[{"PROTECTED B":true}]')
        status, report = self.run_scan('--profile', 'code-with-markings', '--mode', 'changes', '--base', base)
        self.assertEqual((status, len(report['findings'])), (1, 1))
        self.assertEqual(report['findings'][0]['rule'], 'flag_protected_b_en')
        self.assertEqual(report['findings'][0]['severity'], 'HIGH')
        self.assertFalse(report['errors'])


if __name__ == '__main__':
    unittest.main()
