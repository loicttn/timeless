# all databases utilities
import pony.orm as pony
from database.models import State, Instruction, Register, create_db

# all unicorn engine emulation utilities
from unicorn import *
from unicorn.x86_const import *

# all custom objects made from unicorn engine constants
from utils.x86registers import x86registers_table

# all capstone decompiler utilitie
import capstone

# begining of the memory segmentation of the emulated programm
STACK_BASE = 0x0

# size of the emulated program
STACK_SIZE = 1024**2  # 10 MB


class Debugger:
    """
    performs a run of the program and saves all instructions states

    uses unicorn engine to emulate and run the binary
    uses hook with unicorn engine to perform capstone decompilation and
    context saving (registers values, current instruction...)
    """

    def __init__(self: object, binary_infos: dict) -> None:
        """
        initiates Debugger context
        """
        create_db()
        self.emulator = Uc(UC_ARCH_X86, UC_MODE_64)
        self.emulator.mem_map(STACK_BASE, STACK_SIZE)
        self.emulator.mem_write(STACK_BASE, binary_infos.get("content"))
        self.emulator.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 1)

    def _log(self: object, message: str) -> None:
        """
        logs @message

        for debugging purposes
        """
        print(f"[*] {message}")

    def _decompile(self: object, emulator: object, address: int,
                   size: int) -> str:
        """
        returns basic asm code of current instruction

        this method uses the capstone decompiler on the instruction of size
        @size located at @address in the current state of the @emulator
        """
        current_instruction = emulator.mem_read(address, size).decode(errors="ignore")
        code = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for (address, size, mnemonic, op_str) in code.disasm_lite(current_instruction.encode(), address):
            print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))

    def _save_context(self: object, emulator: object, address: int,
                      size: int, data: object) -> str:
        """
        saves current instruction state context

        saves:
        *  all available registers values
        *  instruction @address, @size and @data
        they are all linked to one State() instance which defines the
        current state
        """
        with pony.db_session:
            state = State()
            instruction = Instruction(address=address,
                                      size=size,
                                      data={"data": data},
                                      state=state
                                      )
            for register in x86registers_table:
                try:
                    Register(name=register.get("name"),
                             reg_id=register.get("value"),
                             value=emulator.reg_read(register.get("value")),
                             state=state
                             )
                except UcError:
                    pass

    def _hook_code(self: object, emulator: object,
                   address: int, size: int, data: object) -> None:
        """
        executes code on each instruction
        """
        self._decompile(emulator, address, size)
        self._save_context(emulator, address, size, data)

    def _hook_block(self: object, emulator: object,
                    address: int, size: int, data: object) -> None:
        """
        executes code on each basic bloc
        """
        self._log(f"NEW BASIC BLOC of size {size} at address {hex(address)}")

    def run(self: object) -> None:
        """
        runs next instruction
        """
        self.emulator.hook_add(UC_HOOK_CODE, self._hook_code)
        self.emulator.hook_add(UC_HOOK_BLOCK, self._hook_block)
        # starts after header
        self.emulator.emu_start(STACK_BASE + 64, STACK_BASE + 100)
