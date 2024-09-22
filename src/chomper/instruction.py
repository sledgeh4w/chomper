import re

from unicorn import arm64_const


class AutomicInstruction:
    """Execute an atomic instruction (ldxr, ldadd, ldset, swp, cas).

    The iOS system libraries will use some atomic instructions from ARM v8.1.
    However, Unicorn doesn't support these instructions, so we need to simulation
    them ourselves.
    """

    supports = ("ldxr", "ldadd", "ldset", "swp", "cas")

    def __init__(self, emu, code: bytes):
        self.emu = emu

        self._inst = next(self.emu.cs.disasm_lite(code, 0))

        if not any((self._inst[2].startswith(t) for t in self.supports)):
            raise ValueError("Unsupported instruction: %s" % self._inst[0])

        match = re.match(r"(\w+), \[(\w+)]", self._inst[3])

        if not match:
            match = re.match(r"(\w+), (\w+), \[(\w+)]", self._inst[3])

        if not match:
            raise ValueError("Invalid instruction: %s" % self._inst[3])

        # Parse operation registers
        self._regs = []

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

    def execute(self):
        address = self.read_reg(self._regs[-1])
        value = self.emu.read_int(address, self._op_bits // 8)

        result = None

        if self._inst[2].startswith("ldxr"):
            self.write_reg(self._regs[0], value)

        elif self._inst[2].startswith("ldadd"):
            self.write_reg(self._regs[1], value)
            result = value + self.read_reg(self._regs[0])

        elif self._inst[2].startswith("ldset"):
            self.write_reg(self._regs[1], value)
            result = value | self.read_reg(self._regs[0])

        elif self._inst[2].startswith("swp"):
            self.write_reg(self._regs[1], value)
            result = self.read_reg(self._regs[0])

        elif self._inst[2].startswith("cas"):
            n = self.read_reg(self._regs[0])

            self.write_reg(self._regs[0], value)

            if n == value:
                result = self.read_reg(self._regs[1])

        if result is not None:
            result %= 2**self._op_bits
            self.emu.write_int(address, result, self._op_bits // 8)
