import random
import time
import uuid

from chomper.structs import Timespec


# CTL Types

CTL_UNSPEC = 0
CTL_KERN = 1
CTL_VM = 2
CTL_VFS = 3
CTL_NET = 4
CTL_DEBUG = 5
CTL_HW = 6
CTL_MACHDEP = 7
CTL_USER = 8
CTL_MAXID = 9

# CTL_KERN identifiers

KERN_OSTYPE = 1
KERN_OSRELEASE = 2
KERN_MAXVNODES = 5
KERN_MAXPROC = 6
KERN_ARGMAX = 8
KERN_HOSTNAME = 10
KERN_HOSTID = 11
KERN_CLOCKRATE = 12
KERN_NGROUPS = 18
KERN_SAVED_IDS = 20
KERN_BOOTTIME = 21
KERN_NISDOMAINNAME = 22
KERN_MAXFILESPERPROC = 29
KERN_USRSTACK32 = 35
KERN_USRSTACK64 = 59
KERN_OSVERSION = 65


# CTL_HW identifiers

HW_MACHINE = 1
HW_MODEL = 2
HW_NCPU = 3
HW_BYTEORDER = 4
HW_PHYSMEM = 5
HW_USERMEM = 6
HW_PAGESIZE = 7
HW_VECTORUNIT = 13
HW_CACHELINE = 16
HW_L1ICACHESIZE = 17
HW_L1DCACHESIZE = 18
HW_L2SETTINGS = 19
HW_L2CACHESIZE = 20
HW_TB_FREQ = 23
HW_MEMSIZE = 24
HW_AVAILCPU = 25
HW_TARGET = 26
HW_PRODUCT = 27

# CTL Type map

CTL_TYPE_MAP = {
    (CTL_KERN, KERN_OSTYPE): "kern.ostype",
    (CTL_KERN, KERN_OSRELEASE): "kern.osrelease",
    (CTL_KERN, KERN_MAXVNODES): "kern.maxvnodes",
    (CTL_KERN, KERN_MAXPROC): "kern.maxproc",
    (CTL_KERN, KERN_ARGMAX): "kern.argmax",
    (CTL_KERN, KERN_HOSTNAME): "kern.hostname",
    (CTL_KERN, KERN_HOSTID): "kern.hostid",
    (CTL_KERN, KERN_NGROUPS): "kern.ngroups",
    (CTL_KERN, KERN_SAVED_IDS): "kern.saved_ids",
    (CTL_KERN, KERN_BOOTTIME): "kern.boottime",
    (CTL_KERN, KERN_NISDOMAINNAME): "kern.nisdomainname",
    (CTL_KERN, KERN_MAXFILESPERPROC): "kern.maxfilesperproc",
    (CTL_KERN, KERN_USRSTACK32): "kern.usrstack",
    (CTL_KERN, KERN_USRSTACK64): "kern.usrstack64",
    (CTL_KERN, KERN_OSVERSION): "kern.osversion",
    (CTL_HW, HW_MACHINE): "hw.machine",
    (CTL_HW, HW_MODEL): "hw.model",
    (CTL_HW, HW_TARGET): "hw.target",
    (CTL_HW, HW_PRODUCT): "hw.product",
    (CTL_HW, HW_NCPU): "hw.ncpu",
    (CTL_HW, HW_BYTEORDER): "hw.byteorder",
    (CTL_HW, HW_MEMSIZE): "hw.memsize",
    (CTL_HW, HW_PAGESIZE): "hw.pagesize",
    (CTL_HW, HW_CACHELINE): "hw.cachelinesize",
    (CTL_HW, HW_L1ICACHESIZE): "hw.l1icachesize",
    (CTL_HW, HW_L1DCACHESIZE): "hw.l1dcachesize",
    (CTL_HW, HW_L2CACHESIZE): "hw.l2cachesize",
    (CTL_HW, HW_TB_FREQ): "hw.tbfrequency",
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


def sysctl(ctl_type: int, ctl_ident: int):
    if (ctl_type, ctl_ident) in CTL_TYPE_MAP:
        return KERNEL_PARAMETERS[CTL_TYPE_MAP[(ctl_type, ctl_ident)]]
    return None


def sysctlbyname(name: str):
    return KERNEL_PARAMETERS.get(name)
