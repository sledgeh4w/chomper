import os
import random
import time
import threading

from chomper.types import SyscallHandler


class IosSyscallNo:
    """System call numbers in iOS."""

    GETPID = 0x14
    GETUID = 0x18
    GETEUID = 0x19
    ACCESS = 0x21
    GETEGID = 0x2B
    GETTIMEOFDAY = 0x74
    SHM_OPEN = 0x10A
    GETTID = 0x11E
    ISSETUGID = 0x147
    STAT64 = 0x152
    LSTAT64 = 0x154
    GETENTROPY = 0x1F4

    MACH_ABSOLUTE_TIME_TRAP = 0xFFFFFFFD
    MACH_TIMEBASE_INFO_TRAP = 0xFFFFFFFFFFFFFFA7
    MACH_MSG_TRAP = 0xFFFFFFFFFFFFFFE1
    MACH_REPLY_PORT_TRAP = 0xFFFFFFFFFFFFFFE6

    KERNELRPC_MACH_VM_MAP_TRAP = 0xFFFFFFFFFFFFFFF1


class IosSyscallHandler(SyscallHandler):
    """System call handler for iOS."""

    @classmethod
    def register(cls, emu):
        handlers = {
            IosSyscallNo.GETPID: cls.getpid,
            IosSyscallNo.GETUID: cls.getuid,
            IosSyscallNo.GETEUID: cls.geteuid,
            IosSyscallNo.ACCESS: cls.access,
            IosSyscallNo.GETEGID: cls.getegid,
            IosSyscallNo.GETTIMEOFDAY: cls.gettimeofday,
            IosSyscallNo.SHM_OPEN: cls.shm_open,
            IosSyscallNo.GETTID: cls.gettid,
            IosSyscallNo.ISSETUGID: cls.issetugid,
            IosSyscallNo.STAT64: cls.stat64,
            IosSyscallNo.LSTAT64: cls.lstat64,
            IosSyscallNo.GETENTROPY: cls.getentropy,
            IosSyscallNo.MACH_ABSOLUTE_TIME_TRAP: cls.mach_absolute_time,
            IosSyscallNo.MACH_TIMEBASE_INFO_TRAP: cls.mach_timebase_info_trap,
            IosSyscallNo.MACH_MSG_TRAP: cls.mach_msg_trap,
            IosSyscallNo.MACH_REPLY_PORT_TRAP: cls.mach_reply_port_trap,
            IosSyscallNo.KERNELRPC_MACH_VM_MAP_TRAP: cls.kernelrpc_mach_vm_map_trap,
        }

        emu.syscall_handlers.update(handlers)

    @staticmethod
    def getpid(emu):
        emu.set_retval(os.getpid())

    @staticmethod
    def getuid(emu):
        emu.set_retval(1)

    @staticmethod
    def geteuid(emu):
        emu.set_retval(1)

    @staticmethod
    def access(emu):
        # pathname = emu.read_string(emu.get_arg(0))

        emu.set_retval(0)

    @staticmethod
    def getegid(emu):
        emu.set_retval(1)

    @staticmethod
    def gettimeofday(emu):
        tv = emu.get_arg(0)

        emu.write_u64(tv, int(time.time()))
        emu.write_u64(tv + 8, 0)

        emu.set_retval(0)

    @staticmethod
    def shm_open(emu):
        emu.set_retval(0x80000000)

    @staticmethod
    def gettid(emu):
        tid = threading.current_thread().ident
        emu.set_retval(tid)

    @staticmethod
    def issetugid(emu):
        emu.set_retval(0)

    @staticmethod
    def stat64(emu):
        # path = emu.read_string(emu.get_arg(0))
        stat = emu.get_arg(1)

        # st_mode
        emu.write_u32(stat + 4, 0x4000)

        emu.set_retval(0)

    @staticmethod
    def lstat64(emu):
        # path = emu.read_string(emu.get_arg(0))
        stat = emu.get_arg(1)

        # st_mode
        emu.write_u32(stat + 4, 0x4000)

        emu.set_retval(0)

    @staticmethod
    def getentropy(emu):
        buffer = emu.get_arg(0)
        size = emu.get_arg(1)

        rand_bytes = bytes([random.randint(0, 255) for _ in range(size)])
        emu.write_bytes(buffer, rand_bytes)

        emu.set_retval(0)

    @staticmethod
    def mach_absolute_time(emu):
        emu.set_retval(int(time.time_ns() % (3600 * 10**9)))

    @staticmethod
    def mach_timebase_info_trap(emu):
        info = emu.get_arg(0)

        emu.write_u32(info, 1)
        emu.write_u32(info + 4, 1)

        emu.set_retval(0)

    @staticmethod
    def mach_msg_trap(emu):
        # msg = emu.get_arg(0)

        # msgh_size:
        # emu.write_u32(msg + 0x4, 36)

        # msgh_remote_port
        # emu.write_u32(msg + 0x8, 0)

        # msgh_id
        # emu.write_u32(msg + 0x14, 8100)

        emu.set_retval(6)

    @staticmethod
    def mach_reply_port_trap(emu):
        emu.set_retval(0)

    @staticmethod
    def kernelrpc_mach_vm_map_trap(emu):
        address = emu.get_arg(1)
        size = emu.get_arg(2)

        mem = emu.memory_manager.alloc(size)
        emu.write_pointer(address, mem)

        emu.set_retval(0)
