import os

from unicorn import arm64_const

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS

base_path = os.path.abspath(os.path.dirname(__file__))


def trace_inst_callback(uc, address, size, user_data):
    emu = user_data["emu"]

    inst = next(emu.cs.disasm_lite(uc.mem_read(address, size), 0))
    emu.logger.info(
        f"Trace at {emu.debug_symbol(address)}: {inst[-2]} {inst[-1]}"
    )

    # Display all register status
    regs = []
    for i in range(31):
        regs.append(f"x{i}: {hex(emu.uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X{i}')))}")
    emu.logger.info(", ".join(regs))


def main():
    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "../rootfs/ios"),
        # Trace all modules
        trace_inst=True,
        # Specify custom callback
        trace_inst_callback=trace_inst_callback,
    )

    module_file = os.path.join(
        base_path,
        "../rootfs/ios/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore",
    )

    # Trace target module
    emu.load_module(module_file, trace_inst=True)


if __name__ == '__main__':
    main()
