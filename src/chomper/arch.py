from abc import ABC
from typing import List

from unicorn import arm64_const, arm_const


class Arch(ABC):
    """Adapt to multiple architectures.

    Args:
        name: The name of architecture.
        reg_size: The size of register (bits).
        instr_reg: Register for storing instruction pointer.
        ret_reg: Register for storing return address.
        frame_reg: Register for storing frame pointer.
        stack_reg: Register for storing stack pointer.
        arg_regs: A ``list`` of registers containing stored parameters in order.
        retval_reg: Register for storing return value.
    """

    def __init__(
        self,
        name: str,
        reg_size: int,
        instr_reg: int,
        ret_reg: int,
        stack_reg: int,
        frame_reg: int,
        arg_regs: List[int],
        retval_reg: int,
    ):
        self.name = name
        self.reg_size = reg_size

        self.instr_reg = instr_reg
        self.ret_reg = ret_reg
        self.stack_reg = stack_reg
        self.frame_reg = frame_reg

        self.arg_regs = arg_regs
        self.retval_reg = retval_reg


class ArchArm(Arch):
    """Arch ARM"""

    def __init__(self):
        super().__init__(
            name="ARM",
            reg_size=32,
            instr_reg=arm_const.UC_ARM_REG_PC,
            ret_reg=arm_const.UC_ARM_REG_LR,
            stack_reg=arm_const.UC_ARM_REG_SP,
            frame_reg=arm_const.UC_ARM_REG_FP,
            arg_regs=[
                arm_const.UC_ARM_REG_R0,
                arm_const.UC_ARM_REG_R1,
                arm_const.UC_ARM_REG_R2,
                arm_const.UC_ARM_REG_R3,
            ],
            retval_reg=arm_const.UC_ARM_REG_R0,
        )


class ArchArm64(Arch):
    """Arch ARM64"""

    def __init__(self):
        super().__init__(
            name="ARM64",
            reg_size=64,
            instr_reg=arm64_const.UC_ARM64_REG_PC,
            ret_reg=arm64_const.UC_ARM64_REG_LR,
            stack_reg=arm64_const.UC_ARM64_REG_SP,
            frame_reg=arm64_const.UC_ARM64_REG_FP,
            arg_regs=[
                arm64_const.UC_ARM64_REG_X0,
                arm64_const.UC_ARM64_REG_X1,
                arm64_const.UC_ARM64_REG_X2,
                arm64_const.UC_ARM64_REG_X3,
                arm64_const.UC_ARM64_REG_X4,
                arm64_const.UC_ARM64_REG_X5,
                arm64_const.UC_ARM64_REG_X6,
                arm64_const.UC_ARM64_REG_X7,
            ],
            retval_reg=arm64_const.UC_ARM64_REG_X0,
        )


arch_arm = ArchArm()
arch_arm64 = ArchArm64()
