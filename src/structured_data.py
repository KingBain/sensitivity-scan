"""Extract scalar fields and source lines without executing document content.

No detector names or field aliases belong here. Every field is presented to YARA.
JSON/YAML mappings and XML elements define the boundaries of each record.
"""
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from xml.parsers import expat

import yaml
from yaml import events


MAX_DEPTH = 64
MAX_NODES = 100000
MAX_FIELD_CHARACTERS = 4 * 1024 * 1024
FORMATS = {'.json': 'json', '.yaml': 'yaml', '.yml': 'yaml', '.xml': 'xml'}


class StructureError(Exception):
    """Only fixed messages: parser exceptions can contain sensitive values."""


@dataclass
class Field:
    name: str
    value: str
    line: int


@dataclass
class Node:
    kind: str
    line: int
    value: str = ''
    children: list = field(default_factory=list)


def normalise(record):
    """One quoted key/value per line; escaped newlines cannot forge new fields."""
    lines = [json.dumps(f.name, ensure_ascii=False) + ': ' +
             json.dumps(f.value, ensure_ascii=False) for f in record]
    try:
        return ('\n'.join(lines) + '\n').encode('utf-8'), [f.line for f in record]
    except UnicodeError as exc:
        raise StructureError('Structured fields contain invalid Unicode.') from exc


def yaml_records(text, is_json=False):
    if is_json:
        # Use the JSON decoder to reject YAML-only syntax in a .json file.
        # Events below supply decoded scalars and their original source marks.
        def invalid_constant(value):
            raise StructureError('Invalid JSON constant.')
        json.loads(text, parse_constant=invalid_constant)

    roots, stack, anchors = [], [], {}
    count = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        count += 1
        if count > MAX_NODES:
            raise StructureError('Structured input exceeds the node limit.')
        if isinstance(event, events.DocumentStartEvent):
            anchors = {}
        elif isinstance(event, (events.MappingEndEvent, events.SequenceEndEvent)):
            stack.pop()
        elif isinstance(event, (events.MappingStartEvent, events.SequenceStartEvent,
                                events.ScalarEvent, events.AliasEvent)):
            if isinstance(event, events.AliasEvent):
                if event.anchor not in anchors:
                    raise StructureError('YAML alias has no definition.')
                node = anchors[event.anchor]
            else:
                kind = ('mapping' if isinstance(event, events.MappingStartEvent) else
                        'sequence' if isinstance(event, events.SequenceStartEvent) else 'scalar')
                value = getattr(event, 'value', '')
                if is_json and kind == 'scalar':
                    # JSON combines escaped surrogate pairs; YAML does not.
                    # Preserve number spelling, but decode quoted strings as JSON.
                    raw = text[event.start_mark.index:event.end_mark.index]
                    value = json.loads(raw) if raw.startswith('"') else raw
                node = Node(kind, event.start_mark.line + 1, value)
                if event.anchor:
                    if event.anchor in anchors:
                        raise StructureError('Duplicate YAML anchor.')
                    anchors[event.anchor] = node
            (stack[-1].children if stack else roots).append(node)
            if isinstance(event, (events.MappingStartEvent, events.SequenceStartEvent)):
                stack.append(node)
                if len(stack) > MAX_DEPTH:
                    raise StructureError('Structured input exceeds the nesting limit.')

    records = []
    visits = 0
    characters = 0

    def scalar(name, node):
        nonlocal visits, characters
        visits += 1
        characters += len(name) + len(node.value)
        if visits > MAX_NODES or characters > MAX_FIELD_CHARACTERS:
            raise StructureError('Structured input exceeds the expansion limit.')
        return Field(name, node.value, node.line)

    def walk(node, ancestors=()):
        nonlocal visits
        visits += 1
        if visits > MAX_NODES or len(ancestors) >= MAX_DEPTH:
            raise StructureError('Structured input exceeds the expansion limit.')
        if id(node) in ancestors:
            raise StructureError('Recursive YAML aliases are not supported.')
        ancestors = (*ancestors, id(node))
        if node.kind == 'mapping':
            fields, nested = [], []
            for key, value in zip(node.children[::2], node.children[1::2]):
                if key.kind != 'scalar':
                    raise StructureError('Structured mapping keys must be scalars.')
                if not is_json and key.value == '<<':
                    raise StructureError('Expand YAML merge keys before scanning.')
                if value.kind == 'scalar':
                    fields.append(scalar(key.value, value))
                else:
                    nested.append(value)
            if fields:
                records.append(fields)
            for value in nested:
                walk(value, ancestors)
        elif node.kind == 'sequence':
            for value in node.children:
                walk(value, ancestors)
        else:
            # Scalar array items and scalar documents are independent records.
            records.append([scalar('value', node)])

    for root in roots:
        walk(root)
    return records


@dataclass
class Element:
    name: str
    line: int
    attributes: list
    fields: list = field(default_factory=list)
    text: list = field(default_factory=list)
    text_line: int | None = None
    has_children: bool = False


# Used only to locate attributes in an opening tag already validated by Expat.
# Values (including entity references) come from the XML parser, not this regex.
OPEN_TAG = re.compile(rb'''<(?:[^>"']|"[^"]*"|'[^']*')*>''')
ATTRIBUTE = re.compile(rb'''([^\s=<>/'"]+)\s*=\s*(["'])(.*?)\2''', re.DOTALL)


def xml_records(data):
    parser = expat.ParserCreate(encoding='UTF-8', namespace_separator='}')
    parser.ordered_attributes = True
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    stack, records = [], []
    nodes = 0

    def forbidden(*args):
        raise StructureError('XML DTDs and external entities are not supported.')

    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden

    def start(name, attrs):
        nonlocal nodes
        nodes += 1 + len(attrs) // 2
        if nodes > MAX_NODES or len(stack) >= MAX_DEPTH:
            raise StructureError('XML exceeds the node or nesting limit.')
        if stack:
            stack[-1].has_children = True
        line = parser.CurrentLineNumber
        opening = OPEN_TAG.match(data, parser.CurrentByteIndex)
        if opening is None:
            raise StructureError('Cannot locate XML source attributes.')
        # Namespace declarations are excluded from Expat's attributes list.
        spans = [m for m in ATTRIBUTE.finditer(opening.group())
                 if m.group(1) != b'xmlns' and not m.group(1).startswith(b'xmlns:')]
        if len(spans) != len(attrs) // 2:
            raise StructureError('Cannot map XML attributes to source lines.')
        fields = [Field(attrs[i].rsplit('}', 1)[-1], attrs[i + 1],
                        line + opening.group()[:spans[i // 2].start(3)].count(b'\n'))
                  for i in range(0, len(attrs), 2)]
        stack.append(Element(name.rsplit('}', 1)[-1], line, fields))

    def chars(text):
        if stack:
            element = stack[-1]
            if element.text_line is None and text.strip():
                whitespace = text[:len(text) - len(text.lstrip())]
                element.text_line = parser.CurrentLineNumber + whitespace.count('\n')
            element.text.append(text)

    def end(name):
        element = stack.pop()
        own_fields = element.attributes + element.fields
        value = ''.join(element.text).strip()
        if not element.has_children:
            text_field = Field(element.name, value, element.text_line or element.line)
            if stack:
                stack[-1].fields.append(text_field)
            else:
                own_fields.append(text_field)
        elif value:
            # Direct mixed text is a field, never pooled with descendants.
            own_fields.append(Field('text', value, element.text_line or element.line))
        if own_fields:
            records.append(own_fields)

    parser.StartElementHandler = start
    parser.CharacterDataHandler = chars
    parser.EndElementHandler = end
    parser.Parse(data, True)
    return records


def extract(path, data):
    """Return records, or None for a file handled by the existing text scanner."""
    kind = FORMATS.get(Path(path).suffix.lower())
    if kind is None:
        return None
    try:
        if kind == 'xml':
            return xml_records(data)
        return yaml_records(data.decode('utf-8-sig'), is_json=kind == 'json')
    except StructureError:
        raise
    except (ValueError, UnicodeError, RecursionError, yaml.YAMLError, expat.ExpatError) as exc:
        raise StructureError('Invalid or unsupported structured input.') from exc
