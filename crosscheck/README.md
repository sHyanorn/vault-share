A second implementation of the vault-share share format in Python, written from docs/SPEC.md section 4 and DECISIONS D012 and D019. It shares no code with the web client. CI runs it against the client in both directions and uses it to generate testdata/share_format_test.json.

```bash
# From the repository root, after npm ci in web/
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r crosscheck/requirements.txt
node web/scripts/crosscheck.ts generate client.json
.venv/bin/python crosscheck/crosscheck.py check client.json
.venv/bin/python crosscheck/crosscheck.py generate python.json
node web/scripts/crosscheck.ts check python.json
.venv/bin/python crosscheck/crosscheck.py check-vectors testdata/share_format_test.json
```
