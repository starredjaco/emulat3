import viv_utils
from rich import print

from .consts import *
from .misc import *
from .emulator import *

def emulate_shellcode(
    sc_bytes: bytes,
    base: int = DEFAULT_SC_BASE,
    entry_offset: int = 0,
    max_instructions: int = MAX_INST_SIZE,
    stack_context: int = STACK_CTX,
):
    """
    Load raw x64 shellcode into a vivisect workspace and step through it.

    This uses the same approach as FLOSS for shellcode analysis
    (see floss/main.py which calls viv_utils.getShellcodeWorkspace).
    """
    inst_num = 0 
    suppress_viv_logging()

    entry_point = base + entry_offset
    sc_size = len(sc_bytes)

    print(f"\n[[yellow]*[/yellow]] Shellcode Size:     {sc_size} bytes")
    print(f"[[yellow]*[/yellow]] Base address:       0x{base:x}")
    print(f"[[yellow]*[/yellow]] Entry point:        0x{entry_point:x}")

    # hex dump of the shellcode
    if sc_size <= 256:
        print(f"\n[[magenta]*[/magenta]] Shellcode hex dump:")
        hexdump(sc_bytes, base)
    else:
        print(f"\n[[magenta]*[/magenta]] Shellcode hex dump (first 256 bytes of {sc_size}):")
        hexdump(sc_bytes[:256], base)
    print()

    # load into vivisect as x64 shellcode
    print(f"[[green]*[/green]] Loading shellcode into vivisect workspace...")
    vw = viv_utils.getShellcodeWorkspace(sc_bytes, "amd64", base=base, entry_point=entry_offset)

    # static disassembly from entry point
    print(f"[[blue]*[/blue]] Static disassembly from entry point:\n")
    va = entry_point
    for _ in range(max_instructions):
        if va >= base + sc_size:
            break
        try:
            op = vw.parseOpcode(va)
            print(f"  0x{va:016x}:  {op}")
            va += len(op)
            inst_num += 1
        except Exception:
            print(f"  0x{va:016x}:  <invalid>")
            break
    print()

    print(f"[*] total number of instructions: {inst_num}")
    print(f"[[magenta]*[/magenta]] Creating emulator, stepping up to {max_instructions} instructions...")
    emu = make_emulator(vw)

    # for shellcode, don't stop on ret by default (shellcode may use ret as a trick)
    step_emulator(
        emu, 
        entry_point, 
        inst_num, 
        stop_on_ret=False,
        stack_context=stack_context)

