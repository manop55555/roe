<!-- SPDX-License-Identifier: Apache-2.0 -->
# JSON output schema

Passing `--json` makes every `roe` command emit machine-readable JSON on
stdout. Addresses are `0x`-prefixed lowercase hex **strings** (they may exceed
53 bits); sizes, counts, and byte values are JSON **numbers**. Optional fields
are `null` when absent. The schema is stable within a major version.

## Disassembly (`roe FILE SYMBOL --json`, `--section`, `--all`)

```json
{
  "instructions": [
    {
      "address": "0x11a5",
      "size": 5,
      "bytes": [232, 182, 0, 0, 0],
      "mnemonic": "call",
      "operands": "compute",
      "label": null,
      "branch_target": "0x1160",
      "branch_preview": null,
      "symbol": {
        "name": "main", "raw_name": "main",
        "address": "0x119c", "size": 43,
        "exact": true, "dynamic": false
      },
      "reference": {
        "address": "0x11a5", "name": "compute", "raw_name": "compute",
        "relocation_section": ".rela.text", "relocation_type": 4, "addend": -4
      },
      "string_reference": "compute(20) = %d\n"
    }
  ]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `address` | string | Instruction address (hex). |
| `size` | number | Instruction length in bytes. |
| `bytes` | number[] | Raw instruction bytes. |
| `mnemonic` | string | Instruction mnemonic. |
| `operands` | string | Operand text. |
| `label` | string \| null | Generated label (`L1`…) if this address is a branch target. |
| `branch_target` | string \| null | Resolved absolute branch/call target (hex). |
| `branch_preview` | string \| null | `"L1: <target instruction>"` when the target is in view. |
| `symbol` | object \| null | The function/symbol containing this address. |
| `reference` | object \| null | A relocation/PLT/GOT reference at this instruction. |
| `string_reference` | string \| null | A string literal the instruction's data operand points at. |

`symbol` fields: `name`, `raw_name` (pre-demangle), `address`, `size`, `exact`
(starts exactly here), `dynamic`. `reference` fields: `address`, `name`,
`raw_name`, `relocation_section`, `relocation_type` (ELF `r_type`), `addend`
(number, or `null` for REL relocations).

## Cross-references (`--xref SYMBOL --json`)

```json
{
  "xrefs": [
    { "from": "main", "from_address": "0x119c", "address": "0x11b8",
      "target": "printf", "target_address": "0x1030", "instruction": "call printf@plt" }
  ]
}
```

## Statistics (`--stats --json`)

```json
{
  "stats": [
    { "name": "compute", "address": "0x1160", "size": 60,
      "basic_blocks": 5, "branch_count": 2, "max_nesting_depth": 2 }
  ]
}
```

## File header (`--headers --json`)

```json
{
  "format": "ELF",
  "architecture": "x86-64",
  "type": "executable",
  "endianness": "little",
  "bits": 64,
  "entry": "0x1050"
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `format` | string | Container format (`ELF`, `Mach-O`, `PE`, …). |
| `architecture` | string \| null | Detected architecture; `null` when no object could be loaded. |
| `type` | string | Object kind (`executable`, `shared object`, `relocatable`, …). |
| `endianness` | string | `little` or `big`. |
| `bits` | number | Address width: `32` or `64`. |
| `entry` | string | Entry-point address (hex). |

When `architecture` is `null` the remaining object-derived fields (`type`,
`endianness`, `bits`, `entry`) are omitted.

## Sections (`--sections --json`, or `--json` with section listing)

```json
{
  "sections": [
    { "name": ".text", "address": "0x1050", "size": 401,
      "readable": true, "writable": false, "executable": true }
  ]
}
```

Each entry: `name`, `address` (hex), `size` (number), and the `readable`,
`writable`, `executable` permission booleans.

## Segments (`--segments --json`)

ELF program headers, Mach-O load commands, or PE data directories.

```json
{
  "segments": [
    { "name": "LOAD", "address": "0x1000", "offset": "0x1000", "size": 944,
      "readable": true, "writable": false, "executable": true }
  ]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | Segment/program-header/directory name. |
| `address` | string | Virtual address (hex). |
| `offset` | string | File offset (hex). |
| `size` | number | Size in bytes. |
| `readable` / `writable` / `executable` | bool | Permission flags. |

## Imports (`--imports --json`)

```json
{
  "libraries": ["libc.so.6"],
  "imports": [
    { "name": "printf", "library": "libc.so.6" }
  ]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `libraries` | string[] | Libraries the file depends on. |
| `imports` | object[] | Imported symbols, sorted by library then name. |
| `imports[].name` | string | Imported symbol name. |
| `imports[].library` | string | Providing library (empty string if unbound). |

## Exports (`--exports --json`)

```json
{
  "exports": [
    { "name": "roe_version", "address": "0x1130" }
  ]
}
```

Each entry: `name` (string) and `address` (hex).

## Strings (`--strings --json`)

```json
{
  "strings": [
    { "address": "0x2004", "value": "hello: %d\n", "referenced": true,
      "from": "main", "from_address": "0x11a5" },
    { "address": "0x2010", "value": "unused", "referenced": false }
  ]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `address` | string | Address of the string (hex). |
| `value` | string | The decoded string contents. |
| `referenced` | bool | Whether an instruction references the string. |
| `from` | string | Function that references it. **Present only when `referenced` is `true`.** |
| `from_address` | string | Address of the referencing instruction (hex). **Present only when `referenced` is `true`.** |

Note: unlike most optional fields, `from` and `from_address` are *omitted*
(not set to `null`) when `referenced` is `false`.

## Symbol search (`--find PATTERN --json`)

```json
{
  "pattern": "alloc",
  "matches": [
    { "name": "malloc", "address": "0x1030", "source": "dynsym" }
  ]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `pattern` | string | The search pattern as given. |
| `matches` | object[] | Fuzzy matches. |
| `matches[].name` | string | Matched (demangled) symbol name. |
| `matches[].address` | string | Symbol address (hex). |
| `matches[].source` | string | Originating table: `symtab`, `dynsym`, `import`, or `export`. |

## Function diff (`--diff OTHER --json`)

Emitted by the summary form of `--diff` (no symbol argument). The per-function
unified diff form, `roe NEW --diff OLD SYMBOL`, always prints text and ignores
`--json`.

```json
{
  "added": ["new_helper"],
  "removed": ["old_helper"],
  "changed": ["main"],
  "unchanged": 12
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `added` | string[] | Functions present only in the current file. |
| `removed` | string[] | Functions present only in `OTHER`. |
| `changed` | string[] | Functions present in both but with differing bodies. |
| `unchanged` | number | Count of functions identical in both files. |
