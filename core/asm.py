from unicorn import *
from unicorn.x86_const import *
from keystone import *
from capstone import *
import re

try:
    from core.helper import *
except ImportError:
    from helper import *

def ksAsmX64(CODE):
    try:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        mc, num = ks.asm(CODE)
        return bytes(mc)

    except KsError as e:
        print("ERROR: %s" %e)
        return 0

def ucEmuX64(X86_CODE64):
    # Pass this function some code as a byte string

    # memory address where emulation starts
    ADDRESS = 0x1000000
    STACK_BEGIN = 0x1010000
    out = ""
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64) # Emulator init
    
        ucmemsz = 2 * 1024 * 1024 # This is 2MB which should be enough ram for a small program
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)
    
        mu.mem_write(ADDRESS, X86_CODE64) # Copy the code
        mu.reg_write(UC_X86_REG_RSP, STACK_BEGIN) # Set the stack to a reasonable location (for now)

        out += f"[Memory Size: 0x{ucmemsz:08X} bytes | Base Addr: 0x{ADDRESS:08X} | Stack Begin: 0x{STACK_BEGIN:08X}]\n"
        
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE64)) # emulate code in infinite time & unlimited instructions

        # Print the state at the end of the function
        out += f"RAX: {mu.reg_read(UC_X86_REG_RAX):016X} |     R8: {mu.reg_read(UC_X86_REG_R8):016X}\n"
        out += f"RBX: {mu.reg_read(UC_X86_REG_RBX):016X} |     R9: {mu.reg_read(UC_X86_REG_R9):016X}\n"
        out += f"RCX: {mu.reg_read(UC_X86_REG_RCX):016X} |    R10: {mu.reg_read(UC_X86_REG_R10):016X}\n"
        out += f"RDX: {mu.reg_read(UC_X86_REG_RDX):016X} |    R11: {mu.reg_read(UC_X86_REG_R11):016X}\n"
        out += f"RSP: {mu.reg_read(UC_X86_REG_RSP):016X} |    R12: {mu.reg_read(UC_X86_REG_R12):016X}\n"
        out += f"RBP: {mu.reg_read(UC_X86_REG_RBP):016X} |    R13: {mu.reg_read(UC_X86_REG_R13):016X}\n"
        out += f"RSI: {mu.reg_read(UC_X86_REG_RSI):016X} |    R14: {mu.reg_read(UC_X86_REG_R14):016X}\n"
        out += f"RDI: {mu.reg_read(UC_X86_REG_RDI):016X} |    R15: {mu.reg_read(UC_X86_REG_R15):016X}\n"
        out += f"RIP: {mu.reg_read(UC_X86_REG_RIP):016X} | EFLAGS: {mu.reg_read(UC_X86_REG_EFLAGS):016X}\n"
        out += f" CS: {mu.reg_read(UC_X86_REG_CS):016X} |     SS: {mu.reg_read(UC_X86_REG_SS):016X}\n"
        return out

    except UcError as e:
        return f"Unicorn Error: {e}"

async def x64Handler(room, event, cmdArgs):
    output = "To use, type !x64 emu, then a new line, three backticks and a new line, your code, a new line, then three more backticks. Each line of code can be separated by a new line, or a semicolon."
    x64Task = ""
    args = event.body.split()
    if len(args) < 2:
        return output
    if args[1] == "emu":
        x64Task = "emu"
    asm = event.body
    asmc = re.findall(r"```\n?([^`]+?)\n?```",asm)
    if len(asmc) < 1:
        return output
    if len(asmc[0]) > 0:
        asmBytes = ksAsmX64(asmc[0])
#        print(asmBytes)
        output = fmt1
        output += ucEmuX64(asmBytes)
        output += fmt2
    return output


