# System call numbers

SYS_EXIT = 0x1
SYS_READ = 0x3
SYS_WRITE = 0x4
SYS_OPEN = 0x5
SYS_CLOSE = 0x6
SYS_LINK = 0x9
SYS_UNLINK = 0xA
SYS_CHDIR = 0xC
SYS_FCHDIR = 0xD
SYS_CHMOD = 0xF
SYS_CHOWN = 0x10
SYS_GETPID = 0x14
SYS_GETUID = 0x18
SYS_GETEUID = 0x19
SYS_SENDMSG = 0x1C
SYS_RECVFROM = 0x1D
SYS_ACCESS = 0x21
SYS_CHFLAGS = 0x22
SYS_FCHFLAGS = 0x23
SYS_KILL = 0x25
SYS_GETPPID = 0x27
SYS_PIPE = 0x2A
SYS_GETEGID = 0x2B
SYS_SIGACTION = 0x2E
SYS_SIGPROCMASK = 0x30
SYS_SIGALTSTACK = 0x35
SYS_IOCTL = 0x36
SYS_SYMLINK = 0x39
SYS_READLINK = 0x3A
SYS_MUNMAP = 0x49
SYS_MPROTECT = 0x4A
SYS_MADVISE = 0x4B
SYS_FCNTL = 0x5C
SYS_FSYNC = 0x5F
SYS_SOCKET = 0x61
SYS_CONNECT = 0x62
SYS_SETSOCKOPT = 0x69
SYS_SIGSUSPEND = 0x6F
SYS_GETTIMEOFDAY = 0x74
SYS_GETRUSAGE = 0x75
SYS_GETSOCKOPT = 0x76
SYS_READV = 0x78
SYS_WRITEV = 0x79
SYS_FCHOWN = 0x7B
SYS_FCHMOD = 0x7C
SYS_RENAME = 0x80
SYS_SENDTO = 0x85
SYS_SOCKETPAIR = 0x87
SYS_MKDIR = 0x88
SYS_RMDIR = 0x89
SYS_ADJTIME = 0x8C
SYS_PREAD = 0x99
SYS_PWRITE = 0x9A
SYS_QUOTACTL = 0xA5
SYS_CSOPS = 0xA9
SYS_CSOPS_AUDITTOKEN = 0xAA
SYS_RLIMIT = 0xC2
SYS_SETRLIMIT = 0xC3
SYS_MMAP = 0xC5
SYS_LSEEK = 0xC7
SYS_SYSCTL = 0xCA
SYS_OPEN_DPROTECTED_NP = 0xD8
SYS_GETATTRLIST = 0xDC
SYS_SETXATTR = 0xEC
SYS_FSETXATTR = 0xED
SYS_LISTXATTR = 0xF0
SYS_SHM_OPEN = 0x10A
SYS_SYSCTLBYNAME = 0x112
SYS_GETTID = 0x11E
SYS_IDENTITYSVC = 0x125
SYS_PSYNCH_MUTEXWAIT = 0x12D
SYS_PROCESS_POLICY = 0x143
SYS_ISSETUGID = 0x147
SYS_PROC_INFO = 0x150
SYS_STAT64 = 0x152
SYS_FSTAT64 = 0x153
SYS_LSTAT64 = 0x154
SYS_GETDIRENTRIES64 = 0x158
SYS_STATFS64 = 0x159
SYS_FSTATFS64 = 0x15A
SYS_FSSTAT64 = 0x15B
SYS_BSDTHREAD_CREATE = 0x168
SYS_LCHOWN = 0x16C
SYS_WORKQ_OPEN = 0x16F
SYS_WORKQ_KERNRETURN = 0x170
SYS_KEVENT_QOS = 0x176
SYS_MAC_SYSCALL = 0x17D
SYS_READ_NOCANCEL = 0x18C
SYS_WRITE_NOCANCEL = 0x18D
SYS_OPEN_NOCANCEL = 0x18E
SYS_CLOSE_NOCANCEL = 0x18F
SYS_SENDMSG_NOCANCEL = 0x192
SYS_RECVFROM_NOCANCEL = 0x193
SYS_FCNTL_NOCANCEL = 0x196
SYS_FSYNC_NOCANCEL = 0x198
SYS_CONNECT_NOCANCEL = 0x199
SYS_READV_NOCANCEL = 0x19B
SYS_WRITEV_NOCANCEL = 0x19C
SYS_SENDTO_NOCANCEL = 0x19D
SYS_PREAD_NOCANCEL = 0x19E
SYS_PWRITE_NOCANCEL = 0x19F
SYS_GUARDED_OPEN_NP = 0x1B9
SYS_GUARDED_CLOSE_NP = 0x1BA
SYS_GETATTRLISTBULK = 0x1CD
SYS_OPENAT = 0x1CF
SYS_OPENAT_NOCANCEL = 0x1D0
SYS_RENAMEAT = 0x1D1
SYS_FACCESSAT = 0x1D2
SYS_FCHMODAT = 0x1D3
SYS_FCHOWNAT = 0x1D4
SYS_FSTATAT64 = 0x1D6
SYS_LINKAT = 0x1D7
SYS_UNLINKAT = 0x1D8
SYS_READLINKAT = 0x1D9
SYS_SYMLINKAT = 0x1DA
SYS_MKDIRAT = 0x1DB
SYS_GUARDED_PWRITE_NP = 0x1E6
SYS_PERSONA = 0x1EE
SYS_GETENTROPY = 0x1F4
SYS_NECP_OPEN = 0x1F5
SYS_ULOCK_WAIT = 0x203
SYS_TERMINATE_WITH_PAYLOAD = 0x208
SYS_ABORT_WITH_PAYLOAD = 0x209
SYS_OS_FAULT_WITH_PAYLOAD = 0x211
SYS_PREADV = 0x21C
SYS_PREADV_NOCANCEL = 0x21E

MACH_ABSOLUTE_TIME_TRAP = -0x3
KERNELRPC_MACH_VM_ALLOCATE_TRAP = -0xA
KERNELRPC_MACH_VM_PURGABLE_CONTROL_TRAP = -0xB
KERNELRPC_MACH_VM_DEALLOCATE_TRAP = -0xC
KERNELRPC_MACH_VM_PROTECT_TRAP = -0xE
KERNELRPC_MACH_VM_MAP_TRAP = -0xF
KERNELRPC_MACH_PORT_ALLOCATE_TRAP = -0x10
KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP = -0x16
KERNELRPC_MACH_PORT_CONSTRUCT_TRAP = -0x18
MACH_REPLY_PORT_TRAP = -0x1A
TASK_SELF_TRAP = -0x1C
HOST_SELF_TRAP = -0x1D
MACH_MSG_TRAP = -0x1F
THREAD_GET_SPECIAL_REPLY_PORT = -0x32
HOST_CREATE_MACH_VOUCHER_TRAP = -0x46
KERNELRPC_MACH_PORT_TYPE_TRAP = -0x4C
MACH_TIMEBASE_INFO_TRAP = -0x59
MK_TIMER_CREATE_TRAP = -0x5B

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
KERN_OSREV = 3
KERN_VERSION = 4
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

# Command values for fcntl

F_GETFL = 3
F_GETPATH = 50

# Error codes

EPERM = 1
ENOENT = 2
EBADF = 9
EACCES = 13
EEXIST = 17
ENOTDIR = 20

# mach/port.h

MACH_PORT_TYPE_NONE = 0
MACH_PORT_TYPE_SEND = 1 << (0 + 16)
MACH_PORT_TYPE_RECEIVE = 1 << (1 + 16)
MACH_PORT_TYPE_SEND_ONCE = 1 << (2 + 16)
MACH_PORT_TYPE_PORT_SET = 1 << (3 + 16)
MACH_PORT_TYPE_DEAD_NAME = 1 << (4 + 16)
MACH_PORT_TYPE_LABELH = 1 << (5 + 16)
