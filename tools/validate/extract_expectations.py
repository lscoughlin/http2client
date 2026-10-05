#!/usr/bin/env python3
"""Extract the DECLARED expectation for every h2-client-test-harness test id.

The reference image's verifier only *checks substrings* of the Go client's
error text, so its own wording can disagree with what the harness case author
declared (e.g. 6.2/4 and 5.1/1 are declared ExpectConnectionError but the Go
client reports a stream error whose text still contains the expected token, so
the run logs "Verifier passed" with a stream error). Scoring our client against
the *observed* Go error therefore imports Go's imprecision.

This script parses the verifier sources (the authority) and emits, per id:

    <id>\t<expectation>

where expectation is one of:
    success
    conn-error      ExpectConnectionError(...)
    stream-error    ExpectStreamError(http2.ErrCodeX)

Registrations may reference a named function or an inline func literal, so the
parser works positionally: it slices the source between consecutive
`verifier.Register("<id>",` markers and inspects the Expect* call that follows,
falling back to the named function's body when the registration is a bare name.

Usage:
    python3 tools/validate/extract_expectations.py \
        third_party/h2-client-test-harness/verifier/cases \
        > plan/harness-expectations.tsv
"""
import re
import sys
from pathlib import Path

REGISTER = re.compile(r'verifier\.Register\(\s*"([^"]+)"\s*,')
FUNC = re.compile(r'func\s+(\w+)\s*\(\s*\)\s*error\s*\{(.*?)\n\}', re.S)
KIND = re.compile(r'verifier\.(ExpectConnectionError|ExpectStreamError|'
                  r'ExpectSuccessfulRequest)\s*\(')

KINDS = {
    'ExpectConnectionError': 'conn-error',
    'ExpectStreamError': 'stream-error',
    'ExpectSuccessfulRequest': 'success',
}


def classify_body(body: str) -> str:
    """Map a verifier function body to the expectation it declares."""
    m = KIND.search(body)
    return KINDS.get(m.group(1), '') if m else ''


def main() -> int:
    roots = [Path(p) for p in (sys.argv[1:] or ['.'])]
    files = []
    for root in roots:
        files.extend(sorted(root.rglob('*.go')))
    if not files:
        print('no .go verifier sources found', file=sys.stderr)
        return 1

    table = {}
    unresolved = []
    for path in files:
        text = path.read_text(encoding='utf-8', errors='replace')
        funcs = dict(FUNC.findall(text))
        hits = list(REGISTER.finditer(text))
        for i, m in enumerate(hits):
            tid = m.group(1)
            end = hits[i + 1].start() if i + 1 < len(hits) else len(text)
            window = text[m.end():end]

            kind = classify_body(window)
            if not kind:
                # a bare named function reference: inspect that function body
                name = window.split(',')[0].strip()
                name = re.sub(r'\W+$', '', name)
                kind = classify_body(funcs.get(name, ''))
            if kind:
                table[tid] = kind
            else:
                unresolved.append((tid, window.strip()[:60]))

    for tid in sorted(table):
        print(f'{tid}\t{table[tid]}')

    if unresolved:
        print(f'# unresolved: {len(unresolved)}', file=sys.stderr)
        for tid, ref in unresolved[:20]:
            print(f'#   {tid}: {ref}', file=sys.stderr)
    print(f'# {len(table)} ids resolved from {len(files)} files', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
