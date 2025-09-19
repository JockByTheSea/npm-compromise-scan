# npm-compromised-scan

A small Rust CLI tool to scan your current project's npm dependency tree against a list of known compromised packages.

## Features

- Traverses full `npm ls --all --json` dependency tree.
- Accepts a compromised list with entries:
  - `package-name`
  - `package-name@version`
  - Scoped: `@scope/pkg`
  - Scoped exact: `@scope/pkg@version`
- Outputs matches as:
  - `[EXACT MATCH] name@version`
  - `[NAME MATCH ] name@version`
- Exit code configurable (default 42 when matches found).
- Optional JSON output.
- Can read pre-generated npm JSON (`--npm-json file` or `--npm-json -` for stdin).
- Ignores comments (`# ...`) and blank lines.

## Installation

Download a binary from [Releases](https://github.com/OWNER/REPO/releases) matching your platform, then:

Linux/macOS:

```bash
tar xzf npm-compromised-scan-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
sudo mv npm-compromised-scan /usr/local/bin/
```

Windows (PowerShell):

```powershell
Expand-Archive .\npm-compromised-scan-v0.2.0-x86_64-pc-windows-msvc.zip
Move-Item .\npm-compromised-scan.exe -Destination "C:\Program Files\npm-compromised-scan\npm-compromised-scan.exe"
```

Verify checksum:

```bash
shasum -a 256 -c npm-compromised-scan-v0.2.0-x86_64-unknown-linux-gnu.tar.gz.sha256
```

## Usage

```bash
npm-compromised-scan --list compromised.txt
```

If you do not specify `--npm-json`, the tool runs:

```
npm ls --all --json
```

### Use existing JSON file

```bash
npm ls --all --json > deps.json
npm-compromised-scan --npm-json deps.json
```

### Read JSON from stdin

```bash
npm ls --all --json | npm-compromised-scan --npm-json -
```

### JSON output

```bash
npm-compromised-scan --format json
```

### Custom exit code

```bash
npm-compromised-scan --fail-exit-code 99
```

### Prevent running npm (must provide JSON)

```bash
npm-compromised-scan --no-run-npm --npm-json deps.json
```

## Compromised List Format

Example `compromised.txt`:

```
# Any version of these is bad
event-stream
@bad/evil-lib

# Only certain versions
left-pad@1.3.0
@scope/tool@2.1.4
```

## Exit Codes

- `0`: No matches
- `<fail-exit-code>` (default 42): One or more matches
- Non-zero (different) codes only on internal errors (I/O, JSON parse, etc.)

## Example

```
$ npm-compromised-scan
[EXACT MATCH] left-pad@1.3.0
[NAME MATCH ] event-stream@3.3.6
```

CI usage:

```bash
if ! npm-compromised-scan; then
  rc=$?
  if [ $rc -eq 42 ]; then
    echo "Compromised dependencies found."
    exit 1
  else
    echo "Tool execution error (exit $rc)."
    exit $rc
  fi
fi
```

## Notes

This tool detects presence of packages you deem compromised. For known vulnerabilities, use `npm audit` or services like GitHub Dependabot.
