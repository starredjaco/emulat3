# Emulat3

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/whokilleddb)

Step through x64 PE functions, raw shellcode, or hex coded instructions instruction-by-instruction using [vivisect](https://github.com/vivisect/vivisect) — the same emulation engine that [FLOSS](https://github.com/mandiant/flare-floss) uses internally.

Each step prints:
- Disassembled instruction
- All general-purpose registers + RIP + EFLAGS
- Stack contents around RSP
- Memory writes
- Exceptions (segfaults, invalid instructions, breakpoints)


## Install

Requires Python 3.12+.

```bash
uv sync
```

## Usage

### PE mode

```bash
# Emulate from the entry point
uv run emulat3.py --pe xor.exe

# Emulate a specific function
uv run emulat3.py --pe xor.exe --va 0x140001010 --max 100

# List all functions in the binary
uv run emulat3.py --pe xor.exe --list

# Follow calls into a specific subroutine
uv run emulat3.py --pe xor.exe --va 0x1400014c1 --follow-va 0x140001450

# Follow all calls into non-library subroutines
uv run emulat3.py --pe xor.exe --va 0x1400014c1 --follow-calls
```

### Shellcode mode

```bash
# Raw binary shellcode
uv run emulat3.py --shellcode payload.bin

# Hex-encoded file
uv run emulat3.py --shellcode encoded.txt --hex

# Inline hex string
uv run emulat3.py --sc-hex "4831c04889c7c3"

# \x notation also works
uv run emulat3.py --sc-hex "\x48\x31\xc0\xc3"
```

### Options

| Flag | Description |
|------|-------------|
| `--pe FILE` | PE file to analyze |
| `--va ADDR` | Function virtual address to emulate (hex) |
| `--list` | List all functions in the PE and exit |
| `--shellcode FILE` | Shellcode file (raw binary) |
| `--sc-hex HEX` | Inline hex shellcode string |
| `--hex` | Treat shellcode file as hex-encoded |
| `--base ADDR` | Shellcode base address (default: `0x690000`) |
| `--entry OFFSET` | Entry point offset from base (default: `0`) |
| `--max N` | Max instructions to execute (default: `200`) |
| `--follow-calls` | Step into call instructions instead of skipping them |
| `--follow-va ADDR` | Only step into calls to this specific address |
| `--stack-context N` | Show N qwords before/after RSP each step (default: `4`, `0` to hide) |

## How it works

The emulator is configured to match FLOSS internals:
- 512KB stack, zero-initialized, with RSP centered
- `rep` instructions capped at 256 iterations
- Default vivisect API hooks removed for raw stepping
- All memory writes logged via vivisect's `writelog`

When `--follow-calls` is used, call instructions are executed manually (push return address, set PC to target) instead of letting vivisect skip over function bodies. If a followed call crashes, the emulator rolls back to the pre-call state and lets vivisect handle it as a skip.

## Examples 

```bash
$ uv run emulat3.py --sc-hex "48C7C00A00000048C7C3140000004801D8"
$ uv run emulat3.py --shellcode ./example/code.hex --hex
$ uv run emulat3.py --pe ./example/xor.exe --list
```