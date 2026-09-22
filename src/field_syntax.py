"""Recognize common field syntax in text without selecting a file format.

This is a bounded lexical extractor, not a compiler or document validator.
Containers and indented/list blocks separate records. Code is never evaluated.
"""
from dataclasses import dataclass, field
from html import unescape
import json
import re

MAX_DEPTH = 64
MAX_STEPS = 100000
MAX_FIELD_CHARACTERS = 4 * 1024 * 1024


class StructureError(Exception):
    """Only fixed messages; scanned values must not appear in errors."""


@dataclass
class Field:
    name: str
    value: str
    line: int
    raw: bool = False


@dataclass
class Frame:
    kind: str
    fields: list = field(default_factory=list)


QUOTED = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''
WORD = r"[^\W\d][\w.'’-]*"
PATH_KEY = rf'''[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[[ \t]*(?:{QUOTED})[ \t]*\])+'''
KEY = rf'''(?:{PATH_KEY}|{QUOTED}|{WORD}(?:[ \t]+{WORD})*)'''
ACCESSOR = re.compile(rf'''\.([A-Za-z_$][\w$]*)|\[[ \t]*(?P<quoted>{QUOTED})[ \t]*\]''')
FIELD = re.compile(rf'(?P<key>{KEY})[ \t]*(?P<sep>=>|:(?!=|:)|=(?!=|>))[ \t]*', re.UNICODE)
STRING = re.compile(QUOTED, re.DOTALL)
BARE_WORD = re.compile(r'[\w.-]+', re.UNICODE)
ATTRIBUTE = re.compile(rf'(?P<key>[\w:.-]+)[ \t\r\n]*=[ \t\r\n]*(?P<value>{QUOTED})')
TAG = re.compile(r'''<(?P<closing>/)?(?P<name>[^\W\d][\w:.-]*)(?P<attrs>(?:\s+(?:[^>"']|"[^"]*"|'[^']*')*)?)\s*(?P<selfclosing>/)?>''', re.UNICODE)
CLOSE_TAG = re.compile(r'</(?P<name>[^\W\d][\w:.-]*)\s*>', re.UNICODE)
CONTAINER_LINE = re.compile(rf'^[ \t]*(?:-[ \t]+)?{KEY}[ \t]*[:=][ \t]*(?:(?:#|//).*)?$')
DECLARATION = re.compile(r'^(?:(?:export|public|private|static|final|readonly|const|let|var|string|int|long|float|double|bool|boolean)[ \t]+)+', re.IGNORECASE)
ESCAPE = re.compile(r'\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)', re.DOTALL)


def literal(quoted):
    """Decode common string escapes without eval or language-specific imports."""
    if quoted.startswith('"'):
        try:
            return json.loads(quoted)
        except ValueError:
            pass
    def decode(match):
        token = match.group(1)
        if token[0] in 'ux' and len(token) > 1:
            return chr(int(token[1:], 16))
        return {'n': '\n', 'r': '\r', 't': '\t', '\\': '\\',
                '"': '"', "'": "'", '`': '`'}.get(token, '\\' + token)
    return ESCAPE.sub(decode, quoted[1:-1])


def normalise(record):
    """Expose positive fields to YARA and retain each original value's line."""
    record = [f for f in record if f.value.strip().lower() not in
              ('', 'false', 'null', 'none', 'nil', '~')]
    lines = [(f.value.replace('\r', '\\r').replace('\n', '\\n') if f.raw else
              json.dumps(f.name, ensure_ascii=False) + ': ' + json.dumps(f.value, ensure_ascii=False))
             for f in record]
    try:
        return ('\n'.join(lines) + '\n').encode('utf-8'), [f.line for f in record]
    except UnicodeError as exc:
        raise StructureError('Fields contain invalid Unicode.') from exc


def extract(data):
    """Extract records from UTF-8 text; no filename or extension is needed."""
    text = data.decode('utf-8-sig')
    records = []
    characters = 0
    steps = 0
    property_records = {}

    def frame(kind):
        result = Frame(kind)
        # Retain frames for the scan lifetime: property scope identities must
        # never be recycled when a container closes.
        records.append(result)
        return result

    root = frame('root')
    explicit = [root]
    # (indentation, is_list_item, frame), outside explicit containers only.
    layout = [(0, False, root)]
    pending_container = False
    i, line = 0, 1
    at_line_start = True
    raw, raw_line = [], 1
    # Index closing tags once. C++/TypeScript <T> is not an XML container
    # without a closing tag. No XML entities or DTDs are loaded.
    closes = {}
    for match in CLOSE_TAG.finditer(text):
        closes.setdefault(match.group('name'), []).append(match.start())
    close_indices = {name: 0 for name in closes}

    def current():
        return explicit[-1] if len(explicit) > 1 else layout[-1][2]

    def add(target, name, value, source_line, raw=False):
        nonlocal characters
        characters += len(name) + len(value)
        if characters > MAX_FIELD_CHARACTERS:
            raise StructureError('Field extraction exceeds the size limit.')
        target.fields.append(Field(name, value, source_line, raw))

    def flush():
        if raw:
            add(current(), '', ''.join(raw), raw_line, raw=True)
            raw.clear()

    def push(kind):
        if len(explicit) + len(layout) >= MAX_DEPTH:
            raise StructureError('Field extraction exceeds the nesting limit.')
        result = frame(kind)
        explicit.append(result)
        return result

    def attrs(tag, start, source_line):
        result = []
        for attr in ATTRIBUTE.finditer(tag):
            key = attr.group('key')
            if key == 'xmlns' or key.startswith('xmlns:'):
                continue
            result.append(Field(key.rsplit(':', 1)[-1],
                                unescape(literal(attr.group('value'))),
                                source_line + text[start:start + attr.start('value')].count('\n')))
        return result

    def add_attrs(target, fields):
        for item in fields:
            add(target, item.name, item.value, item.line)

    while i < len(text):
        steps += 1
        if steps > MAX_STEPS:
            raise StructureError('Field extraction exceeds the token limit.')
        if at_line_start:
            end = text.find('\n', i)
            end = len(text) if end < 0 else end
            source = text[i:end]
            spaces = len(source) - len(source.lstrip(' \t'))
            indent = len(source[:spaces].expandtabs(4))
            rest = source[spaces:]
            if len(explicit) == 1 and rest.strip() in ('---', '...'):
                root = frame('root')
                explicit[0] = root
                layout = [(0, False, root)]
                pending_container = False
                i = end
                at_line_start = False
                continue
            item = re.match(r'-([ \t]+|$)', rest)
            if rest.strip() and len(explicit) == 1:
                while len(layout) > 1 and (layout[-1][0] > indent or
                        (layout[-1][0] == indent and (item or layout[-1][1]))):
                    layout.pop()
                if item or (pending_container and indent > layout[-1][0]):
                    if len(layout) >= MAX_DEPTH:
                        raise StructureError('Field extraction exceeds the nesting limit.')
                    layout.append((indent, bool(item), frame('layout')))
                pending_container = bool(CONTAINER_LINE.fullmatch(source))
            i += spaces + (item.end() if item and len(explicit) == 1 else 0)
            at_line_start = False
            if i >= len(text):
                break
        char = text[i]
        if char == '\n':
            flush()
            i += 1
            line += 1
            at_line_start = True
            continue

        tag = TAG.match(text, i) if char == '<' else None
        if tag:
            name = tag.group('name')
            candidates = closes.get(name, [])
            index = close_indices.get(name, 0)
            while index < len(candidates) and candidates[index] < tag.end():
                index += 1
            close_indices[name] = index
            closing = candidates[index] if index < len(candidates) else None
            selfclosing = tag.group().rstrip().endswith('/>')
            if tag.group('closing'):
                flush()
                for n in range(len(explicit) - 1, 0, -1):
                    if explicit[n].kind == 'xml:' + name:
                        del explicit[n:]
                        break
            elif selfclosing or closing is not None:
                flush()
                attributes = attrs(tag.group(), i, line)
                if selfclosing:
                    add_attrs(frame('xml:' + name), attributes)
                elif '<' not in text[tag.end():closing]:
                    target = frame('xml:' + name) if attributes else current()
                    add_attrs(target, attributes)
                    value = text[tag.end():closing]
                    leading = value[:len(value) - len(value.lstrip())]
                    source_line = line + text[i:tag.end()].count('\n') + leading.count('\n')
                    add(target, name.rsplit(':', 1)[-1], unescape(value.strip()), source_line)
                    end_tag = CLOSE_TAG.match(text, closing)
                    line += text[i:end_tag.end()].count('\n')
                    i = end_tag.end()
                    continue
                else:
                    add_attrs(push('xml:' + name), attributes)
            else:
                tag = None
            if tag:
                line += text[i:tag.end()].count('\n')
                i = tag.end()
                continue

        if char in '{[(':
            flush()
            push({'{': '}', '[': ']', '(': ')'}[char])
            i += 1
            continue
        if char in '}])':
            flush()
            for n in range(len(explicit) - 1, 0, -1):
                if explicit[n].kind == char:
                    del explicit[n:]
                    break
            i += 1
            continue

        match = FIELD.match(text, i)
        if match:
            start = match.end()
            value_string = STRING.match(text, start)
            if value_string:
                end = value_string.end()
                value = literal(value_string.group())
            else:
                end = start
                while end < len(text) and text[end] not in '\r\n,;{}[]()<>':
                    end += 1
                value = re.split(r'\s+(?://|#|/\*)', text[start:end], maxsplit=1)[0].strip()
            flush()
            if value:
                key = match.group('key').strip()
                target = current()
                if key[0] in '\"\'`':
                    key = literal(key)
                else:
                    if match.group('sep') == '=':
                        key = DECLARATION.sub('', key)
                    if re.fullmatch(PATH_KEY, key):
                        accessors = list(ACCESSOR.finditer(key))
                        parts = [key[:accessors[0].start()]] + [literal(a.group('quoted')) if a.group('quoted') else a.group(1) for a in accessors]
                        identity = (id(target), tuple(parts[:-1]))
                        if identity not in property_records:
                            property_records[identity] = frame('property')
                        target = property_records[identity]
                        key = parts[-1]
                add(target, key, value, line + text[i:start].count('\n'))
            line += text[i:end].count('\n')
            i = end
            continue

        string = STRING.match(text, i)
        if string:
            flush()
            add(current(), '', literal(string.group()), line, raw=True)
            line += text[i:string.end()].count('\n')
            i = string.end()
            continue
        if not raw:
            raw_line = line
        word = BARE_WORD.match(text, i)
        end = word.end() if word else i + 1
        raw.append(text[i:end])
        i = end

    flush()
    return [record.fields for record in records if record.fields]
