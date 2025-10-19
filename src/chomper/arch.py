from typing import List

from unicorn import arm64_const, arm_const


class Arch:
    def __init__(
        self,
        nbits: int,
        reg_pc: int,
        reg_sp: int,
        reg_fp: int,
        reg_lr: int,
        reg_args: List[int],
        reg_retval: int,
        reg_float_retval: int,
        reg_double_retval: int,
    ):
        self.nbits = nbits

        self.reg_pc = reg_pc
        self.reg_sp = reg_sp
        self.reg_fp = reg_fp
        self.reg_lr = reg_lr

        self.reg_args = reg_args
        self.reg_retval = reg_retval
        self.reg_float_retval = reg_float_retval
        self.reg_double_retval = reg_double_retval

    @property
    def addr_size(self) -> int:
        return self.nbits // 8


arm_arch = Arch(
    nbits=32,
    reg_pc=arm_const.UC_ARM_REG_PC,
    reg_sp=arm_const.UC_ARM_REG_SP,
    reg_fp=arm_const.UC_ARM_REG_FP,
    reg_lr=arm_const.UC_ARM_REG_LR,
    reg_args=[
        arm_const.UC_ARM_REG_R0,
        arm_const.UC_ARM_REG_R1,
        arm_const.UC_ARM_REG_R2,
        arm_const.UC_ARM_REG_R3,
    ],
    reg_retval=arm_const.UC_ARM_REG_R0,
    reg_float_retval=arm_const.UC_ARM_REG_S0,
    reg_double_retval=arm_const.UC_ARM_REG_D0,
)

arm64_arch = Arch(
    nbits=64,
    reg_pc=arm64_const.UC_ARM64_REG_PC,
    reg_sp=arm64_const.UC_ARM64_REG_SP,
    reg_fp=arm64_const.UC_ARM64_REG_FP,
    reg_lr=arm64_const.UC_ARM64_REG_LR,
    reg_args=[
        arm64_const.UC_ARM64_REG_X0,
        arm64_const.UC_ARM64_REG_X1,
        arm64_const.UC_ARM64_REG_X2,
        arm64_const.UC_ARM64_REG_X3,
        arm64_const.UC_ARM64_REG_X4,
        arm64_const.UC_ARM64_REG_X5,
        arm64_const.UC_ARM64_REG_X6,
        arm64_const.UC_ARM64_REG_X7,
    ],
    reg_retval=arm64_const.UC_ARM64_REG_X0,
    reg_float_retval=arm64_const.UC_ARM64_REG_S0,
    reg_double_retval=arm64_const.UC_ARM64_REG_D0,
)
