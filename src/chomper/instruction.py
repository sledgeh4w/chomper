from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Sequence, TYPE_CHECKING

from unicorn import arm64_const

if TYPE_CHECKING:
    from .core import Chomper


INST_ARG_PATTERNS = [
    re.compile(r"(\w+), (\w+), \[(\w+)]"),
    re.compile(r"(\w+), \[(\w+)]"),
    re.compile(r"(\w+), (\w+)"),
    re.compile(r"(\w+)"),
]


class BaseInstruction(ABC):
    """Extend instructions not supported by Unicorn."""

    SUPPORTS: Sequence[str]

    def __init__(self, emu: Chomper, code: bytes):
        self.emu = emu

        self._inst = next(self.emu.cs.disasm_lite(code, 0))

        if not any((self._inst[2].startswith(t) for t in self.SUPPORTS)):
            raise ValueError("Unsupported instruction: %s" % self._inst[0])

        # Parse operation registers
        self._regs = []

        if self._inst[3]:
            match = None

            for pattern in INST_ARG_PATTERNS:
                match = pattern.match(self._inst[3])
                if match:
                    break

            if not match:
                raise ValueError("Invalid instruction: %s" % self._inst[3])

            for reg in match.groups():
                attr = f"UC_ARM64_REG_{reg.upper()}"
                self._regs.append(getattr(arm64_const, attr))

        # Parse operation bits
        if self._inst[2].endswith("b"):
            self._op_bits = 8
        elif re.search(r"w(\d+)", self._inst[3]):
            self._op_bits = 32
        else:
            self._op_bits = 64

    def read_reg(self, reg_id: int) -> int:
        if reg_id in (arm64_const.UC_ARM64_REG_WZR, arm64_const.UC_ARM64_REG_XZR):
            return 0

        return self.emu.uc.reg_read(reg_id)

    def write_reg(self, reg_id: int, value: int):
        self.emu.uc.reg_write(reg_id, value)

    def exec_next(self):
        next_addr = self.read_reg(self.emu.arch.reg_pc) + 4
        self.write_reg(self.emu.arch.reg_pc, next_addr)

    @abstractmethod
    def execute(self):
        pass


class AutomicInstruction(BaseInstruction):
    """Extend atomic instructions.

    The iOS system libraries will use atomic instructions from ARM v8.1.
    """

    SUPPORTS = ("ldxr", "ldadd", "ldset", "ldclr", "swp", "cas")

    def execute(self):
        inst_str = self._inst[2]
        address = self.read_reg(self._regs[-1])
        value = self.emu.read_int(address, self._op_bits // 8)

        result = None

        if inst_str.startswith("ldxr"):
            self.write_reg(self._regs[0], value)
        elif inst_str.startswith("ldadd"):
            self.write_reg(self._regs[1], value)
            result = value + self.read_reg(self._regs[0])
        elif inst_str.startswith("ldset"):
            self.write_reg(self._regs[1], value)
            result = value | self.read_reg(self._regs[0])
        elif inst_str.startswith("ldclr"):
            self.write_reg(self._regs[1], value)
            result = value & self.read_reg(self._regs[0])
        elif inst_str.startswith("swp"):
            self.write_reg(self._regs[1], value)
            result = self.read_reg(self._regs[0])
        elif inst_str.startswith("cas"):
            n = self.read_reg(self._regs[0])

            self.write_reg(self._regs[0], value)

            if n == value:
                result = self.read_reg(self._regs[1])

        if result is not None:
            result %= 2**self._op_bits
            self.emu.write_int(address, result, self._op_bits // 8)

        self.exec_next()


class PACInstruction(BaseInstruction):
    """Extend PAC instructions.

    The iOS system libraries for the arm64e architecture will use PAC
    instructions.
    """

    SUPPORTS = ("braa", "blraaz", "retab", "paciza")

    def execute(self):
        inst_str = self._inst[2]

        if inst_str == "braa":
            call_addr = self.read_reg(self._regs[0])
            self.write_reg(self.emu.arch.reg_pc, call_addr)
        elif inst_str == "blraaz":
            call_addr = self.read_reg(self._regs[0])
            ret_addr = self.read_reg(self.emu.arch.reg_pc) + 4
            self.write_reg(self.emu.arch.reg_pc, call_addr)
            self.write_reg(self.emu.arch.reg_lr, ret_addr)
        elif inst_str == "retab":
            ret_addr = self.read_reg(self.emu.arch.reg_lr)
            self.write_reg(self.emu.arch.reg_pc, ret_addr)
        elif inst_str in ("paciza",):
            self.exec_next()


EXTEND_INSTRUCTIONS = [AutomicInstruction, PACInstruction]
