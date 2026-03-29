from rich import print
import logging

def banner():
    print(r"""
███████╗███╗   ███╗██╗   ██╗██╗      █████╗ ████████╗██████╗ 
██╔════╝████╗ ████║██║   ██║██║     ██╔══██╗╚══██╔══╝╚════██╗
█████╗  ██╔████╔██║██║   ██║██║     ███████║   ██║    █████╔╝
██╔══╝  ██║╚██╔╝██║██║   ██║██║     ██╔══██║   ██║    ╚═══██╗
███████╗██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║   ██║   ██████╔╝
╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═════╝ 

                                                [yellow]@whokilleddb[/yellow]""")

def parse_hex_string(hex_str: str) -> bytes:
    """Parse a hex string like '31c0c3' or '\\x31\\xc0\\xc3'."""
    cleaned = hex_str.replace("\\x", "").replace("0x", "").replace(" ", "")
    return bytes.fromhex(cleaned)


def suppress_viv_logging():
    for name in ("vivisect", "vivisect.base", "vivisect.impemu", "vtrace", "envi", "envi.codeflow"):
        logging.getLogger(name).setLevel(logging.ERROR)

def hexdump(data, base_addr=0, width=16):
    """Produce a classic hex dump of bytes."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        lines.append(f"  0x{base_addr + offset:08x}: {hex_part:<{width * 3}}  {ascii_part}")
    
    print()
    for line in lines:
        print(f"  {line}")

