import random
import time
import uuid

from chomper.structs import Timespec
from chomper.utils import log_call

from . import const

# CTL Type map
CTL_TYPE_MAP = {
    (const.CTL_KERN, const.KERN_OSTYPE): "kern.ostype",
    (const.CTL_KERN, const.KERN_OSRELEASE): "kern.osrelease",
    (const.CTL_KERN, const.KERN_MAXVNODES): "kern.maxvnodes",
    (const.CTL_KERN, const.KERN_MAXPROC): "kern.maxproc",
    (const.CTL_KERN, const.KERN_ARGMAX): "kern.argmax",
    (const.CTL_KERN, const.KERN_HOSTNAME): "kern.hostname",
    (const.CTL_KERN, const.KERN_HOSTID): "kern.hostid",
    (const.CTL_KERN, const.KERN_NGROUPS): "kern.ngroups",
    (const.CTL_KERN, const.KERN_SAVED_IDS): "kern.saved_ids",
    (const.CTL_KERN, const.KERN_BOOTTIME): "kern.boottime",
    (const.CTL_KERN, const.KERN_NISDOMAINNAME): "kern.nisdomainname",
    (const.CTL_KERN, const.KERN_MAXFILESPERPROC): "kern.maxfilesperproc",
    (const.CTL_KERN, const.KERN_USRSTACK32): "kern.usrstack",
    (const.CTL_KERN, const.KERN_USRSTACK64): "kern.usrstack64",
    (const.CTL_KERN, const.KERN_OSVERSION): "kern.osversion",
    (const.CTL_HW, const.HW_MACHINE): "hw.machine",
    (const.CTL_HW, const.HW_MODEL): "hw.model",
    (const.CTL_HW, const.HW_TARGET): "hw.target",
    (const.CTL_HW, const.HW_PRODUCT): "hw.product",
    (const.CTL_HW, const.HW_NCPU): "hw.ncpu",
    (const.CTL_HW, const.HW_BYTEORDER): "hw.byteorder",
    (const.CTL_HW, const.HW_MEMSIZE): "hw.memsize",
    (const.CTL_HW, const.HW_PAGESIZE): "hw.pagesize",
    (const.CTL_HW, const.HW_CACHELINE): "hw.cachelinesize",
    (const.CTL_HW, const.HW_L1ICACHESIZE): "hw.l1icachesize",
    (const.CTL_HW, const.HW_L1DCACHESIZE): "hw.l1dcachesize",
    (const.CTL_HW, const.HW_L2CACHESIZE): "hw.l2cachesize",
    (const.CTL_HW, const.HW_TB_FREQ): "hw.tbfrequency",
}

# Kernel parameters
KERNEL_PARAMETERS = {
    "kern.ostype": "Darwin",
    "kern.osrelease": "20.1.0",
    "kern.maxvnodes": 5700,
    "kern.maxproc": 2000,
    "kern.argmax": "262144",
    "kern.hostname": "iPhone",
    "kern.hostid": 0,
    "kern.ngroups": 16,
    "kern.saved_ids": 1,
    "kern.boottime": Timespec.from_time_ns(
        time.time_ns() - random.randint(8, 24) * 3600 * 10**9
    ),
    "kern.nisdomainname": "",
    "kern.maxfilesperproc": 10240,
    "kern.ipc.maxsockbuf": 6291456,
    "kern.usrstack": 1840496640,
    "kern.usrstack64": 6135463936,
    "kern.osversion": "18B121",
    "kern.osproductversion": "14.2.1",
    "kern.bootargs": "",
    "kern.bootsessionuuid": str(uuid.uuid4()).upper(),
    "kern.memorystatus_level": 32,
    "kern.secure_kernel": 1,
    "kern.waketime": Timespec.from_time_ns(
        time.time_ns() - random.randint(1800, 3600) * 10**9
    ),
    "kern.monotonicclock": 10931883,
    "kern.monotonicclock_rate_usecs": 30,
    "kern.monotoniclock_offset_usecs": 1728527904498687,
    "kern.osvariant_status": 8070450536327063592,
    "hw.machine": "iPhone13,1",
    "hw.model": "D52gAP",
    "hw.target": "D52gAP",
    "hw.product": "iPhone",
    "hw.ncpu": 6,
    "hw.byteorder": 1234,
    "hw.memsize": 3899293696,
    "hw.activecpu": 6,
    "hw.physicalcpu": 6,
    "hw.physicalcpu_max": 6,
    "hw.logicalcpu": 6,
    "hw.logicalcpu_max": 6,
    "hw.cputype": 16777228,
    "hw.cpusubtype": 2,
    "hw.cpu64bit_capable": 1,
    "hw.cpufamily": 458787763,
    "hw.pagesize": 16384,
    "hw.cachelinesize": 128,
    "hw.l1icachesize": 131072,
    "hw.l1dcachesize": 65536,
    "hw.l2cachesize": 4194304,
    "hw.tbfrequency": 24000000,
    "security.mac.sandbox.sentinel": ".sb-b524d45c",
}


@log_call
def sysctl(ctl_type: int, ctl_ident: int):
    if (ctl_type, ctl_ident) in CTL_TYPE_MAP:
        return KERNEL_PARAMETERS[CTL_TYPE_MAP[(ctl_type, ctl_ident)]]
    return None


@log_call
def sysctlbyname(name: str):
    result = KERNEL_PARAMETERS.get(name)

    if name == "kern.osvariant_status" and isinstance(result, int):
        # can_has_debugger = 3
        result |= 3 << 2

        # internal_release_type = 3
        result |= 3 << 4

    return result
