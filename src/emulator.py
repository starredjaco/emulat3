import envi
import envi.exc
import viv_utils
from rich import print
import viv_utils.emulator_drivers

from .consts import *

# See: https://github.com/mandiant/flare-floss/blob/7b6f2410ea5c12981aef2e8b050b5a92c85575bf/floss/utils.py#L115
def make_emulator(vw):
    """Create an emulator with FLOSS-like settings (see floss/utils.py:make_emulator)."""
    emu = vw.getEmulator(logwrite=True, taintbyte=b"\x00") # record every memory write, fill unwritten spaces with 0x00

    # This is a workaround for a vivisect bug (copied from FLOSS). Vivisect's default emulator creates a stack region during init, but it's too small and positioned poorly. This iterates the memory snapshot in reverse, finds the [stack] segment by name, deletes it, writes the snapshot back, and clears stack_map_base so the next call to initStackMemory allocates a fresh one instead of reusing the old mapping.
    memory_snap = emu.getMemorySnap()
    for i in range(len(memory_snap) - 1, -1, -1):
        _, _, info, _ = memory_snap[i]
        if info[3] == STACK_MEM_NAME:
            del memory_snap[i]
            emu.setMemorySnap(memory_snap)
            emu.stack_map_base = None
            break

    # Half a MB of stack
    stack_size = int(0.5 * MEGABYTE)
    emu.initStackMemory(stacksize=stack_size)

    # zero-fill the stack (overwrite taint bytes)
    emu.writeMemory(emu.stack_map_base, b"\x00" * stack_size)

    # Move stack pointer to middle of the memory
    emu.setStackCounter(emu.getStackCounter() - int(0.25 * MEGABYTE))
    
    # Caps rep-prefixed instructions (like rep movsb, rep stosb) at 256 iterations per step. Without this, a rep with a large RCX could loop millions of times and hang the emulator.
    emu.setEmuOpt("i386:repmax", 256)

    # Removes vivisect's built-in hooks that auto-handle calls to known API functions (like malloc, strlen, etc.). We want raw stepping — the emulator should execute or skip calls as we decide, not silently simulate library behavior behind the scenes.
    viv_utils.emulator_drivers.remove_default_viv_hooks(emu)
    return emu

def disasm(emu, va) -> str:
    """Disassemble one instruction at va."""
    try:
        op = emu.parseOpcode(va)
        return str(op)
    except Exception as e:
        return f"<disasm error: {e}>"

def is_safe_to_follow(vw, emu, op):
    """
    Decide whether a call should be followed into.
    Only follow calls to non-library functions defined in the binary.
    Skip imports, thunks, and indirect calls to tainted pointers.
    """
    try:
        target = op.getOperValue(0, emu)
    except Exception:
        return False

    if target is None or target == 0:
        return False

    # only follow calls to known functions in the workspace
    if target not in vw.getFunctions():
        return False

    # skip library functions (detected via FLIRT signatures)
    try:
        import viv_utils.flirt
        if viv_utils.flirt.is_library_function(vw, target):
            return False
    except Exception:
        pass

    return True

def get_reg_names() -> list:
    return AMD64_REGS

def format_registers(emu) -> str:
    """Format current register values into a readable block."""
    lines = []
    reg_names = get_reg_names()
    row = []
    for i, name in enumerate(reg_names):
        val = emu.getRegisterByName(name)
        row.append(f"{name:>4s}=0x{val:016x}")
        if len(row) == 4 or i == len(reg_names) - 1:
            lines.append("  ".join(row))
            row = []

    # program counter and flags
    pc = emu.getProgramCounter()
    eflags = emu.getRegisterByName("eflags")
    lines.append(f"  rip=0x{pc:016x}  eflags=0x{eflags:08x} [{format_flags(eflags)}]")
    return "\n".join(lines)


def format_flags(eflags: int) -> str:
    """Format EFLAGS register into readable flag names."""
    parts = []
    for bit, name in EFLAGS:
        if eflags & (1 << bit):
            parts.append(name)
    return " ".join(parts) if parts else "(none)"

def format_stack(emu, context: int = 4) -> str:
    """Format stack around the current stack pointer.
    Shows `context` qwords before and after SP."""
    sp = emu.getStackCounter()
    lines = []
    # from high address (before SP) down to low address (after SP)
    start = sp - (context * 8)
    end = sp + (context * 8)
    for addr in range(end, start - 8, -8):
        try:
            val = emu.readMemoryFormat(addr, "<Q")[0]
            marker = " <-- RSP" if addr == sp else ""
            lines.append(f"  0x{addr:016x}: 0x{val:016x}{marker}")
        except Exception:
            marker = " <-- RSP" if addr == sp else ""
            lines.append(f"  0x{addr:016x}: ????????????????{marker}")
    return "\n".join(lines)

def do_call_manually(emu, op):
    """
    Manually execute a call instruction by pushing the return address
    and setting PC to the target, bypassing vivisect's checkCall() which
    skips function bodies.
    Returns True if the call was followed, False if it should be skipped.
    """
    try:
        target = op.getOperValue(0, emu)
    except Exception:
        return False

    if target is None or target == 0:
        return False

    # check if the target is valid code (not an unmapped region)
    try:
        emu.parseOpcode(target)
    except Exception:
        return False

    # return address is the instruction right after the call
    ret_addr = op.va + len(op)
    # push return address onto the stack
    sp = emu.getStackCounter()
    sp -= 8
    emu.setStackCounter(sp)
    emu.writeMemory(sp, ret_addr.to_bytes(8, "little"))
    emu.setProgramCounter(target)
    return True

def format_write(va, data) -> str:
    """Format a single memory write entry for display."""
    ascii_repr = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in data)
    return f"  >> mem write: [0x{va:016x}] <- {data.hex()} \"{ascii_repr}\""

def step_emulator(
    emu, 
    start_va, 
    max_instructions = MAX_INST_SIZE, 
    stop_on_ret=True,
    follow_calls=False, follow_va=None, vw=None,
    stack_context: int = STACK_CTX):
    """
    Step through instructions one at a time from start_va.
    Prints register state, memory writes, and exceptions at each step.

    If follow_calls=True, call instructions are executed manually so
    the emulator steps into subroutines instead of skipping them.
    """
    emu.setProgramCounter(start_va)
    
    # track call depth so we can stop on the right ret
    call_depth = 0

    print(f"\n[[green]*[/green]] Initial state:")
    print(format_registers(emu))
    if stack_context > 0:
        print(f"\n  Stack:")
        print(format_stack(emu, stack_context))

    # snapshot writelog length before stepping so we skip emulator init writes
    baseline_wlog_len = len(emu.getPathProp("writelog"))
    prev_wlog_len = baseline_wlog_len
    snap = None
    snap_wlog_len = 0
    step = 0

    print(f"\n{'=' * 78}")

    while step < max_instructions:
        pc = emu.getProgramCounter()
        step += 1

        insn_str = disasm(emu, pc)

        print(f"\nStep [yellow]{step:>4d}[/yellow] | [magenta]0x{pc:016x}[/magenta]: [cyan]{insn_str}[/cyan]")
        print(f"{'-' * 78}")

        # execute one instruction
        try:
            # if follow_calls, manually handle call/ret for depth tracking
            if follow_calls and vw is not None:
                op = emu.parseOpcode(pc)
                if op.mnem == "call":
                    # only follow direct calls from the top-level function (depth 0)
                    should_follow = False
                    target = None
                    if call_depth == 0:
                        try:
                            target = op.getOperValue(0, emu)
                        except Exception:
                            pass
                        if target is not None:
                            if follow_va is not None:
                                # --follow-va: only follow calls to this specific address
                                should_follow = (target == follow_va)
                            else:
                                # --follow-calls: follow all safe calls
                                should_follow = is_safe_to_follow(vw, emu, op)

                    if should_follow and target is not None:
                        # save full state so we can roll back if the call crashes
                        snap = emu.getEmuSnap()
                        snap_wlog_len = len(emu.getPathProp("writelog"))
                        if do_call_manually(emu, op):
                            call_depth += 1
                            print(f"  >> following call to 0x{target:x}")
                            print(format_registers(emu))
                            wlog = emu.getPathProp("writelog")
                            if len(wlog) > prev_wlog_len:
                                for _, va, data in wlog[prev_wlog_len:]:
                                    print(format_write(va, data))
                                prev_wlog_len = len(wlog)
                            continue
                elif op.mnem == "ret" and call_depth > 0:
                    call_depth -= 1

            emu.stepi()
        except (envi.exc.BreakpointHit, envi.InvalidInstruction,
                envi.SegmentationViolation, Exception) as e:
            # if we're inside a followed call and it crashes, roll back
            # and let vivisect skip the call instead
            if call_depth > 0 and snap is not None:
                emu.setEmuSnap(snap)
                prev_wlog_len = snap_wlog_len
                call_depth = 0
                snap = None
                # re-execute the original call instruction with default stepi
                print(f"  !! call crashed ({type(e).__name__}), rolling back and skipping")
                try:
                    emu.stepi()
                except Exception:
                    pass
                print(format_registers(emu))
                wlog = emu.getPathProp("writelog")
                if len(wlog) > prev_wlog_len:
                    for _, va, data in wlog[prev_wlog_len:]:
                        print(format_write(va, data))
                    prev_wlog_len = len(wlog)
                continue

            if isinstance(e, envi.SegmentationViolation):
                print(f"  !! SEGFAULT at 0x{pc:x}: {e}")
                print(f"     (memory access to unmapped region)")
                print(f"\n  Registers at crash:")
                print(format_registers(emu))
            elif isinstance(e, envi.exc.BreakpointHit):
                print(f"  !! BREAKPOINT: {e}")
            elif isinstance(e, envi.InvalidInstruction):
                print(f"  !! INVALID INSTRUCTION at 0x{pc:x}: {e}")
            else:
                print(f"  !! EXCEPTION at 0x{pc:x}: {type(e).__name__}: {e}")
            break

        # print registers
        print(format_registers(emu))
        if stack_context > 0:
            print(f"\n  Stack:")
            print(format_stack(emu, stack_context))

        # check for new memory writes
        wlog = emu.getPathProp("writelog")
        if len(wlog) > prev_wlog_len:
            for _, va, data in wlog[prev_wlog_len:]:
                print(format_write(va, data))
            prev_wlog_len = len(wlog)

        # stop on ret (only at the top-level function, not inside sub-calls)
        if stop_on_ret and insn_str.strip().startswith("ret") and call_depth == 0:
            print(f"\n[*] Function returned after {step} steps")
            break

        # stop if PC lands on 0x0 (likely end of shellcode)
        new_pc = emu.getProgramCounter()
        if new_pc == 0:
            print(f"\n[*] PC reached 0x0 after {step} steps (likely end of shellcode)")
            break

    # else:
    #     print(f"\n[!] Reached max instruction limit ({max_instructions})")

    # final summary
    print(f"\n{'=' * 78}")
    print(f"\n[[green]*[/green]] Final state after [green]{step}[/green] steps:")
    print(format_registers(emu))

    # stack dump
    sp = emu.getStackCounter()
    print(f"\n[[magenta]*[/magenta]] Stack around SP [yellow](0x{sp:x})[/yellow]:")
    for offset in range(0x30, -0x18, -8):
        addr = sp - offset
        try:
            val = emu.readMemoryFormat(addr, "<Q")[0]
            marker = " <-- SP" if addr == sp else ""
            print(f"  0x{addr:016x}: 0x{val:016x}{marker}")
        except Exception:
            pass

    # memory write summary (only writes from actual instruction stepping, not emulator init)
    wlog = emu.getPathProp("writelog")
    user_writes = wlog[baseline_wlog_len:]
    if user_writes:
        print(f"\n[[red]*[/red]] Memory writes during emulation ({len(user_writes)} total):")
        for _, va, data in user_writes:
            ascii_repr = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in data)
            print(f"  [0x{va:016x}] <- {data.hex():20s} \"{ascii_repr}\"")

    print(f"\n[[green]*[/green]] Done.")
    return step
