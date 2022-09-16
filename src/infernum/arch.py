from unicorn import arm_const, arm64_const
from .structs import Arch


# ARM
arch_arm = Arch(
    name="ARM",
    reg_size=32,
    reg_sp=arm_const.UC_ARM_REG_SP,
    reg_fp=arm_const.UC_ARM_REG_FP,
    reg_lr=arm_const.UC_ARM_REG_LR,
    reg_pc=arm_const.UC_ARM_REG_PC,
    reg_args=[
        arm_const.UC_ARM_REG_R0,
        arm_const.UC_ARM_REG_R1,
        arm_const.UC_ARM_REG_R2,
        arm_const.UC_ARM_REG_R3,
    ],
    reg_ret=arm_const.UC_ARM_REG_R0,
)


# ARM64
arch_arm64 = Arch(
    name="ARM64",
    reg_size=64,
    reg_sp=arm64_const.UC_ARM64_REG_SP,
    reg_fp=arm64_const.UC_ARM64_REG_FP,
    reg_lr=arm64_const.UC_ARM64_REG_LR,
    reg_pc=arm64_const.UC_ARM64_REG_PC,
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
    reg_ret=arm64_const.UC_ARM64_REG_X0,
)
