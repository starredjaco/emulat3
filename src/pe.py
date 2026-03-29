import os
import vivisect
import viv_utils
from rich import print
from typing import Optional

from .misc import *
from .emulator import *

def resolve_function_name(vw, fva) -> str:
    """Resolve function name using multiple vivisect methods."""
    # vw.getName() returns import names and sub_XXX for unknowns
    name = vw.getName(fva)
    if name and not name.startswith("sub_"):
        # strip the address suffix vivisect appends to import names (e.g. strlen_1400028a0)
        suffix = f"_{fva:x}"
        if name.endswith(suffix):
            name = name[: -len(suffix)]
        return name

    # fall back to viv_utils which checks FLIRT signatures
    api_name = viv_utils.get_function_name(vw, fva)
    if api_name:
        return api_name

    return None

def list_functions(pe):
    """Print all functions in the workspace."""
    vw = viv_utils.getWorkspace(pe)
    functions = sorted(vw.getFunctions())
    print(f"[[yellow]*[/yellow]] [green]{len(functions)}[/green] functions found:\n")
    print(f"  {'VA':<20s}  {'Size':>5s}  Name")
    print(f"  {'-' * 18}  {'-' * 5}  {'-' * 40}")
    for fva in functions:
        name = resolve_function_name(vw, fva) or "(unnamed)"
        try:
            size = vw.getFunctionMetaDict(fva).get("Size", 0)
        except Exception:
            size = 0
        print(f"  0x{fva:016x}  {size:>5d}  {name}")

def load_shellcode_bytes(path: str, is_hex: bool) -> bytes:
    """Read shellcode from a file. Supports raw binary or hex-encoded."""
    with open(path, "rb") as f:
        raw = f.read()
    if is_hex:
        # strip whitespace, handle \x notation
        text = raw.decode("ascii", errors="ignore")
        text = text.replace("\\x", "").replace(" ", "").replace("\n", "").replace("\r", "")
        return bytes.fromhex(text)
    return raw

def get_arch(vw) -> str:
    return vw.getMeta("Architecture")

def emulate_pe(pe_path: str, function_va: Optional[int] = None, max_instructions: int = 200,
               follow_calls: bool = False, follow_va: Optional[int] = None,
               stack_context: int = 4):
    """Load a PE and step through a function."""
    suppress_viv_logging()
    print(f"[[cyan]*[/cyan]] Loading [green]{os.path.basename(pe_path)}[/green] into vivisect workspace")
    vw = viv_utils.getWorkspace(pe_path)
    print(f"[[magenta]*[/magenta]] Architecture: {get_arch(vw)}")

    if function_va is None:
        function_va = vw.getEntryPoints()[0]
        print(f"[[red]*[/red]] No function VA given, using entry point: [green]0x{function_va:x}[/green]")
    else:
        print(f"[[red]*[/red]] Target function: [blue]0x{function_va:x}[blue]")

    try:
        fname = resolve_function_name(vw, function_va) or "(unnamed)"
        print(f"[[yellow]*[/yellow]] Function name: {fname}")
    except Exception:
        print(f"[[yellow]*[/yellow]] Address [yellow]0x{function_va:x}[/yellow] is not a function entry (mid-function start)")

        # show static disassembly
    try:
        f = viv_utils.Function(vw, function_va)
        insn_count = sum(len(bb.instructions) for bb in f.basic_blocks)
        print(f"[[blue]*[/blue]] Static disassembly ({insn_count} instructions):\n")
        for bb in f.basic_blocks:
            for insn in bb.instructions:
                print(f"  0x{insn.va:016x}:  {insn}")
        print()
    except Exception:
        print("[[red]*[/red]] Could not statically disassemble function\n")

    print(f"[[green]*[/green]] Creating emulator, stepping up to {max_instructions} instructions...")
    if follow_va is not None:
        print(f"[[cyan]*[/cyan]] Following calls to 0x{follow_va:x}")
    elif follow_calls:
        print(f"[[cyan]*[/cyan]] Following calls into subroutines")

    emu = make_emulator(vw)
    step_emulator(emu, function_va, max_instructions, stop_on_ret=True,
                  follow_calls=follow_calls or (follow_va is not None),
                  follow_va=follow_va, vw=vw, stack_context=stack_context)