import os
from rich import print


from src.pe import *
from src.misc import *
from src.cliargs import build_parser
from src.shellcode import emulate_shellcode

def main():
    parser = build_parser()
    args = parser.parse_args()
    banner()

    # shellcode from inline hex
    if args.sc_hex:
        print("[[green]*[/green]] Parsing Hex Codes....")
        sc_bytes = parse_hex_string(args.sc_hex.strip())
        emulate_shellcode(sc_bytes, args.base, args.entry, args.max, stack_context=args.stack_context)
        return

    if args.shellcode:
        print("[[green]*[/green]] Parsing Shellcode....")
        sc_bytes = load_shellcode_bytes(args.shellcode, args.hex)
        emulate_shellcode(sc_bytes, args.base, args.entry, args.max, stack_context=args.stack_context)
        return

    if not args.pe:
        parser.print_help()
        sys.exit(1)

    if args.list:
        pe = os.path.abspath(args.pe)
        print(f"[[cyan]*[/cyan]] Listing functions from PE: [magenta]{pe}[/magenta]")
        list_functions(pe)
        return

    pe = os.path.abspath(args.pe)
    emulate_pe(pe, args.va, args.max,
               follow_calls=args.follow_calls, follow_va=args.follow_va,
               stack_context=args.stack_context)


if __name__ == '__main__':
    main()