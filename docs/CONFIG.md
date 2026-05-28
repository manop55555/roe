<!-- SPDX-License-Identifier: Apache-2.0 -->
# Configuration

`roe` reads an optional TOML configuration file for defaults. **Command-line
flags always override the config file**, which in turn overrides the built-in
defaults.

## Location

`roe` looks for the file in this order:

1. `$ROE_CONFIG` — if set, this exact path is used.
2. Platform default:
   - **Linux/BSD:** `$XDG_CONFIG_HOME/roe/config.toml`, or
     `~/.config/roe/config.toml` if `XDG_CONFIG_HOME` is unset.
   - **macOS:** `~/Library/Application Support/roe/config.toml`.
   - **Windows:** `%APPDATA%\roe\config.toml`.

A missing or unreadable file is not an error; the built-in defaults apply.

## Keys

`roe` parses a simple TOML subset: `key = value` lines, `# comments`, and
`[table]` headers (table names are ignored; keys are read flat). Booleans accept
`true`/`false` (also `yes`/`no`, `on`/`off`, `1`/`0`). Strings may be quoted.

| Key          | Type    | Default  | Effect                                                      |
| ------------ | ------- | -------- | ----------------------------------------------------------- |
| `color`      | boolean | `true`   | Allow ANSI color; the default `--color=auto` then emits it only when stdout is a TTY. `--color=<auto\|always\|never>` / `--no-color` / `NO_COLOR` override. |
| `pager`      | boolean | `true`   | Page long output through `$PAGER`. `--no-pager`/`NO_PAGER` also disable. |
| `show_bytes` | boolean | `false`  | Show raw instruction bytes (like `--show-bytes`).           |
| `source`     | boolean | `false`  | Interleave source lines when available (like `--source`).   |
| `syntax`     | string  | `intel`  | x86 assembly syntax: `intel` or `att`.                      |

## Example

```toml
# ~/.config/roe/config.toml
color = true
pager = true
show_bytes = false
source = false
syntax = "intel"
```

## Precedence

For each setting, the value used is, in order of priority:

1. the relevant command-line flag, if present;
2. the environment variable (`NO_COLOR`, `NO_PAGER`) where one exists;
3. the config file value;
4. the built-in default.

Because `--no-color` and `--no-pager` only *disable*, setting `color = false` or
`pager = false` in the config is the way to turn those off by default. To force
color on even when piped (e.g. into `less -R`), use `--color=always`, which
overrides `NO_COLOR` and the non-TTY default.
