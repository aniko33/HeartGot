import pefile
import capstone
import argparse
import io
import os

from sys import stderr

from stone_color.messages import *
from stone_color.color import DefaultColors as dcolor

UNWIN_HEADER = os.path.join(os.path.dirname(__file__), "unwin.h")
MACRO_SYSCALL_C = r"""#define GEN_SYSCALL64(SSN) __asm volatile (   \
    "mov r10, rcx\n"                        \
    "mov eax, " SSN "\n"                    \
    "syscall\n"                             \
)
"""


parser = argparse.ArgumentParser(
    prog="HeartGot",
    description="Extract SSNs from NTDLL functions"
)

parser.add_argument("dllPath", type=argparse.FileType("rb"))
parser.add_argument("-f", "--functions", nargs="+")
parser.add_argument("-g", "--generate-header", action="store_true")
parser.add_argument("-v", "--verbose", action="store_true")

def generate_func(name: str, ssn: str | int) -> str:
    if isinstance(ssn, int):
        ssn = str(hex(ssn))

    unwin_content = open(UNWIN_HEADER, "r").read()
    func_signature = re.search(name + r"\([^)]*\)", unwin_content)

    if func_signature is None:
        errorf("Function signature not found")
        quit(1)

    func_signature = "__stdcall NTSTATUS syscall_" + func_signature.group().strip()

    return formatf(func_signature, "{\n" + f"\tGEN_SYSCALL64(\"{ssn}\");" + "\n}")

def main():
    args = parser.parse_args()
    dllpath: io.TextIOWrapper = args.dllPath
    generate_header: bool = args.generate_header
    verbose: bool = args.verbose
    functions: list[str] = args.functions

    if verbose:
        infof("Loading PE... ", end="")

    text_section = None
    pe = pefile.PE(data=dllpath.read())

    if verbose:
        printf(dcolor.green + "LOADED" + dcolor.reset, file=stderr)

    for section in pe.sections:
        if section.Name.startswith(b".text"):
            text_section = section

    if text_section is None:
        errorf(".text section not found!")
        return

    exported_functions = {}
    found_functions = {}

    for funcs in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        exported_functions[funcs.name] = funcs.address

    for function in functions:
        if function.encode() in exported_functions:
            found_functions[function] = exported_functions[function.encode()]
        else:
            warnf(f"{function} not found!")

    if found_functions == None:
        errorf("Any functions found!")
        return

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    header_generated = "#include \"unwin.h\"\n#ifndef HEARTDIRECT_H_\n#define HEARTDIRECT_H_\n\n" + MACRO_SYSCALL_C + "\n\n"

    for fname, faddr in found_functions.items():
        file_offset = text_section.PointerToRawData + (faddr - text_section.VirtualAddress) 
        data = pe.get_data(faddr, 10)
        instructions = list(md.disasm(data, file_offset))

        if verbose:
            printf("=" * 10 + f" [ { dcolor.highred + fname + dcolor.reset} ] " + "=" * 10, file=stderr)
            infof("Func addr:", hex(faddr))
            infof("File Offset:", hex(file_offset))
            infof("Instructions:", instructions)

        try:
            SSN_number = hex(int(instructions[1].op_str.split(", ")[1], 16)) 

            if verbose:
                successf("SSN:", dcolor.highcyan + SSN_number + dcolor.reset)
                printf(file=stderr)
        except Exception as e:
            errorf("Invalid parse instruction args:", e)
            raise e

        if not generate_header and not verbose:
            successf(f"{fname} SSN:", SSN_number)
        else:
            header_generated += generate_func(fname, SSN_number) + "\n"

    header_generated += "\n#endif"

    if verbose and generate_header:
        printf("=" * 10 + f" [ {dcolor.highred + "Header generated" + dcolor.reset} ] " + "=" * 10, file=stderr)

    if generate_header:
        printf(header_generated)

if __name__ == "__main__":
    main()
