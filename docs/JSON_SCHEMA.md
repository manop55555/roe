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

## Sections (`--json` with section listing)

```json
{
  "sections": [
    { "name": ".text", "address": "0x1050", "size": 401,
      "readable": true, "writable": false, "executable": true }
  ]
}
```
