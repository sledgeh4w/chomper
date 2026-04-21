from __future__ import annotations

import ctypes
import os
import random
import time
from typing import Callable

from unicorn import arm64_const

from chomper.exceptions import SystemOperationFailed, ProgramTerminated
from chomper.os.posix import SyscallError
from chomper.os.syscall import BaseSyscallHandler
from chomper.utils import to_signed, struct_to_bytes, read_struct

from . import const
from .structs import (
    Timespec,
    Rlimit,
    Rusage,
    ProcBsdinfo,
    ProcBsdshortinfo,
    ProcUniqidentifierinfo,
)
from .sysctl import sysctl, sysctlbyname


SYSCALL_ERRORS = {
    SyscallError.EPERM: (const.EPERM, "EPERM"),
    SyscallError.ENOENT: (const.ENOENT, "ENOENT"),
    SyscallError.EBADF: (const.EBADF, "EBADF"),
    SyscallError.EACCES: (const.EACCES, "EACCES"),
    SyscallError.EFAULT: (const.EFAULT, "EFAULT"),
    SyscallError.EEXIST: (const.EEXIST, "EEXIST"),
    SyscallError.ENOTDIR: (const.ENOTDIR, "ENOTDIR"),
    SyscallError.EINVAL: (const.EINVAL, "EINVAL"),
    SyscallError.EMFILE: (const.EMFILE, "EMFILE"),
    SyscallError.ETIMEDOUT: (const.ETIMEDOUT, "ETIMEDOUT"),
}

# Used by `getrlimit`
RESOURCE_LIMITS = {
    const.RLIMIT_CPU: (const.RLIM_INFINITY, const.RLIM_INFINITY),
    const.RLIMIT_FSIZE: (const.RLIM_INFINITY, const.RLIM_INFINITY),
    const.RLIMIT_DATA: (const.RLIM_INFINITY, const.RLIM_INFINITY),
    const.RLIMIT_STACK: (0xFC000, 0xFC000),
    const.RLIMIT_CORE: (0, const.RLIM_INFINITY),
    const.RLIMIT_RSS: (const.RLIM_INFINITY, const.RLIM_INFINITY),
    const.RLIMIT_MEMLOCK: (const.RLIM_INFINITY, const.RLIM_INFINITY),
    const.RLIMIT_NPROC: (1333, 2000),
    const.RLIMIT_NOFILE: (0x1C00, const.RLIM_INFINITY),
}


class IosSyscallHandler(BaseSyscallHandler):
    """Handle iOS system calls."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        names = {
            const.SYS_SYSCALL: "SYS_syscall",
            const.SYS_EXIT: "SYS_exit",
            const.SYS_FORK: "SYS_fork",
            const.SYS_READ: "SYS_read",
            const.SYS_WRITE: "SYS_write",
            const.SYS_OPEN: "SYS_open",
            const.SYS_CLOSE: "SYS_close",
            const.SYS_LINK: "SYS_link",
            const.SYS_UNLINK: "SYS_unlink",
            const.SYS_CHDIR: "SYS_chdir",
            const.SYS_FCHDIR: "SYS_fchdir",
            const.SYS_CHMOD: "SYS_chmod",
            const.SYS_CHOWN: "SYS_chown",
            const.SYS_GETPID: "SYS_getpid",
            const.SYS_GETUID: "SYS_getuid",
            const.SYS_GETEUID: "SYS_geteuid",
            const.SYS_SENDMSG: "SYS_sendmsg",
            const.SYS_RECVFROM: "SYS_recvfrom",
            const.SYS_GETPEERNAME: "SYS_getpeername",
            const.SYS_GETSOCKNAME: "SYS_getsockname",
            const.SYS_ACCESS: "SYS_access",
            const.SYS_CHFLAGS: "SYS_chflags",
            const.SYS_FCHFLAGS: "SYS_fchflags",
            const.SYS_KILL: "SYS_kill",
            const.SYS_GETPPID: "SYS_getppid",
            const.SYS_DUP: "SYS_dup",
            const.SYS_PIPE: "SYS_pipe",
            const.SYS_GETEGID: "SYS_getegid",
            const.SYS_SIGACTION: "SYS_sigaction",
            const.SYS_GETGID: "SYS_getgid",
            const.SYS_SIGPROCMASK: "SYS_sigprocmask",
            const.SYS_GETLOGIN: "SYS_getlogin",
            const.SYS_SETLOGIN: "SYS_setlogin",
            const.SYS_SIGALTSTACK: "SYS_sigaltstack",
            const.SYS_IOCTL: "SYS_ioctl",
            const.SYS_REBOOT: "SYS_reboot",
            const.SYS_SYMLINK: "SYS_symlink",
            const.SYS_READLINK: "SYS_readlink",
            const.SYS_MSYNC: "SYS_msync",
            const.SYS_MUNMAP: "SYS_munmap",
            const.SYS_MPROTECT: "SYS_mprotect",
            const.SYS_MADVISE: "SYS_madvise",
            const.SYS_SETPGID: "SYS_setpgid",
            const.SYS_DUP2: "SYS_dup2",
            const.SYS_FCNTL: "SYS_fcntl",
            const.SYS_SELECT: "SYS_select",
            const.SYS_FSYNC: "SYS_fsync",
            const.SYS_SETPRIORITY: "SYS_setpriority",
            const.SYS_SOCKET: "SYS_socket",
            const.SYS_CONNECT: "SYS_connect",
            const.SYS_GETPRIORITY: "SYS_getpriority",
            const.SYS_BIND: "SYS_bind",
            const.SYS_SETSOCKOPT: "SYS_setsockopt",
            const.SYS_LISTEN: "SYS_listen",
            const.SYS_SIGSUSPEND: "SYS_sigsuspend",
            const.SYS_GETTIMEOFDAY: "SYS_gettimeofday",
            const.SYS_GETRUSAGE: "SYS_getrusage",
            const.SYS_GETSOCKOPT: "SYS_getsockopt",
            const.SYS_READV: "SYS_readv",
            const.SYS_WRITEV: "SYS_writev",
            const.SYS_FCHOWN: "SYS_fchown",
            const.SYS_FCHMOD: "SYS_fchmod",
            const.SYS_RENAME: "SYS_rename",
            const.SYS_FLOCK: "SYS_flock",
            const.SYS_SENDTO: "SYS_sendto",
            const.SYS_SOCKETPAIR: "SYS_socketpair",
            const.SYS_MKDIR: "SYS_mkdir",
            const.SYS_RMDIR: "SYS_rmdir",
            const.SYS_UTIMES: "SYS_utimes",
            const.SYS_FUTIMES: "SYS_futimes",
            const.SYS_ADJTIME: "SYS_adjtime",
            const.SYS_GETPGID: "SYS_getpgid",
            const.SYS_PREAD: "SYS_pread",
            const.SYS_PWRITE: "SYS_pwrite",
            const.SYS_QUOTACTL: "SYS_quotactl",
            const.SYS_CSOPS: "SYS_csops",
            const.SYS_CSOPS_AUDITTOKEN: "SYS_csops_audittoken",
            const.SYS_GETRLIMIT: "SYS_getrlimit",
            const.SYS_SETRLIMIT: "SYS_setrlimit",
            const.SYS_MMAP: "SYS_mmap",
            const.SYS_LSEEK: "SYS_lseek",
            const.SYS_FTRUNCATE: "SYS_ftruncate",
            const.SYS_SYSCTL: "SYS_sysctl",
            const.SYS_MLOCK: "SYS_mlock",
            const.SYS_MUNLOCK: "SYS_munlock",
            const.SYS_OPEN_DPROTECTED_NP: "SYS_open_dprotected_np",
            const.SYS_GETATTRLIST: "SYS_getattrlist",
            const.SYS_SETXATTR: "SYS_setxattr",
            const.SYS_FSETXATTR: "SYS_fsetxattr",
            const.SYS_LISTXATTR: "SYS_listxattr",
            const.SYS_SHM_OPEN: "SYS_shm_open",
            const.SYS_SYSCTLBYNAME: "SYS_sysctlbyname",
            const.SYS_GETTID: "SYS_gettid",
            const.SYS_IDENTITYSVC: "SYS_identitysvc",
            const.SYS_PSYNCH_MUTEXWAIT: "SYS_psynch_mutexwait",
            const.SYS_PROCESS_POLICY: "SYS_process_policy",
            const.SYS_ISSETUGID: "SYS_issetugid",
            const.SYS_PTHREAD_SIGMASK: "SYS_pthread_sigmask",
            const.SYS_SEMWAIT_SIGNAL: "SYS_semwait_signal",
            const.SYS_PROC_INFO: "SYS_proc_info",
            const.SYS_STAT64: "SYS_stat64",
            const.SYS_FSTAT64: "SYS_fstat64",
            const.SYS_LSTAT64: "SYS_lstat64",
            const.SYS_GETDIRENTRIES64: "SYS_getdirentries64",
            const.SYS_STATFS64: "SYS_statfs64",
            const.SYS_FSTATFS64: "SYS_fstatfs64",
            const.SYS_FSSTAT64: "SYS_fsstat64",
            const.SYS_BSDTHREAD_CREATE: "SYS_bsdthread_create",
            const.SYS_KQUEUE: "SYS_kqueue",
            const.SYS_KEVENT: "SYS_kevent",
            const.SYS_LCHOWN: "SYS_lchown",
            const.SYS_WORKQ_OPEN: "SYS_workq_open",
            const.SYS_WORKQ_KERNRETURN: "SYS_workq_kernreturn",
            const.SYS_THREAD_SELFID: "SYS_thread_selfid",
            const.SYS_KEVENT_QOS: "SYS_kevent_qos",
            const.SYS_KEVENT_ID: "SYS_kevent_id",
            const.SYS_MAC_SYSCALL: "SYS_mac_syscall",
            const.SYS_READ_NOCANCEL: "SYS_read_nocancel",
            const.SYS_WRITE_NOCANCEL: "SYS_write_nocancel",
            const.SYS_OPEN_NOCANCEL: "SYS_open_nocancel",
            const.SYS_CLOSE_NOCANCEL: "SYS_close_nocancel",
            const.SYS_SENDMSG_NOCANCEL: "SYS_sendmsg_nocancel",
            const.SYS_RECVFROM_NOCANCEL: "SYS_recvfrom_nocancel",
            const.SYS_FCNTL_NOCANCEL: "SYS_fcntl_nocancel",
            const.SYS_SELECT_NOCANCEL: "SYS_select_nocancel",
            const.SYS_FSYNC_NOCANCEL: "SYS_fsync_nocancel",
            const.SYS_CONNECT_NOCANCEL: "SYS_connect_nocancel",
            const.SYS_READV_NOCANCEL: "SYS_readv_nocancel",
            const.SYS_WRITEV_NOCANCEL: "SYS_writev_nocancel",
            const.SYS_SENDTO_NOCANCEL: "SYS_sendto_nocancel",
            const.SYS_PREAD_NOCANCEL: "SYS_pread_nocancel",
            const.SYS_PWRITE_NOCANCEL: "SYS_pwrite_nocancel",
            const.SYS_SEMWAIT_SIGNAL_NOCANCEL: "SYS_semwait_signal_nocancel",
            const.SYS_GUARDED_OPEN_NP: "SYS_guarded_open_np",
            const.SYS_GUARDED_CLOSE_NP: "SYS_guarded_close_np",
            const.SYS_GETATTRLISTBULK: "SYS_getattrlistbulk",
            const.SYS_CLONEFILEAT: "SYS_clonefileat",
            const.SYS_OPENAT: "SYS_openat",
            const.SYS_OPENAT_NOCANCEL: "SYS_openat_nocancel",
            const.SYS_RENAMEAT: "SYS_renameat",
            const.SYS_FACCESSAT: "SYS_faccessat",
            const.SYS_FCHMODAT: "SYS_fchmodat",
            const.SYS_FCHOWNAT: "SYS_fchownat",
            const.SYS_FSTATAT64: "SYS_fstatat64",
            const.SYS_LINKAT: "SYS_linkat",
            const.SYS_UNLINKAT: "SYS_unlinkat",
            const.SYS_READLINKAT: "SYS_readlinkat",
            const.SYS_SYMLINKAT: "SYS_symlinkat",
            const.SYS_MKDIRAT: "SYS_mkdirat",
            const.SYS_BSDTHREAD_CTL: "SYS_bsdthread_ctl",
            const.SYS_GUARDED_PWRITE_NP: "SYS_guarded_pwrite_np",
            const.SYS_PERSONA: "SYS_persona",
            const.SYS_GETENTROPY: "SYS_getentropy",
            const.SYS_NECP_OPEN: "SYS_necp_open",
            const.SYS_ULOCK_WAIT: "SYS_ulock_wait",
            const.SYS_TERMINATE_WITH_PAYLOAD: "SYS_terminate_with_payload",
            const.SYS_ABORT_WITH_PAYLOAD: "SYS_abort_with_payload",
            const.SYS_OS_FAULT_WITH_PAYLOAD: "SYS_os_fault_with_payload",
            const.SYS_PREADV: "SYS_preadv",
            const.SYS_PREADV_NOCANCEL: "SYS_preadv_nocancel",
            const.MACH_ABSOLUTE_TIME_TRAP: "MACH_ABSOLUTE_TIME_TRAP",
            const.KERNELRPC_MACH_VM_ALLOCATE_TRAP: "KERNELRPC_MACH_VM_ALLOCATE_TRAP",
            const.KERNELRPC_MACH_VM_PURGABLE_CONTROL_TRAP: "KERNELRPC_MACH_VM_PURGABLE_CONTROL_TRAP",
            const.KERNELRPC_MACH_VM_DEALLOCATE_TRAP: "KERNELRPC_MACH_VM_DEALLOCATE_TRAP",
            const.KERNELRPC_MACH_VM_PROTECT_TRAP: "KERNELRPC_MACH_VM_PROTECT_TRAP",
            const.KERNELRPC_MACH_VM_MAP_TRAP: "KERNELRPC_MACH_VM_MAP_TRAP",
            const.KERNELRPC_MACH_PORT_ALLOCATE_TRAP: "KERNELRPC_MACH_PORT_ALLOCATE_TRAP",
            const.KERNELRPC_MACH_PORT_DEALLOCATE_TRAP: "KERNELRPC_MACH_PORT_DEALLOCATE_TRAP",
            const.KERNELRPC_MACH_PORT_MOD_REFS_TRAP: "KERNELRPC_MACH_PORT_MOD_REFS_TRAP",
            const.KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP: "KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP",
            const.KERNELRPC_MACH_PORT_CONSTRUCT_TRAP: "KERNELRPC_MACH_PORT_CONSTRUCT_TRAP",
            const.KERNELRPC_MACH_PORT_DESTRUCT_TRAP: "KERNELRPC_MACH_PORT_DESTRUCT_TRAP",
            const.MACH_REPLY_PORT_TRAP: "MACH_REPLY_PORT_TRAP",
            const.THREAD_SELF_TRAP: "THREAD_SELF_TRAP",
            const.TASK_SELF_TRAP: "TASK_SELF_TRAP",
            const.HOST_SELF_TRAP: "HOST_SELF_TRAP",
            const.MACH_MSG_TRAP: "MACH_MSG_TRAP",
            const.SEMAPHORE_SIGNAL_TRAP: "SEMAPHORE_SIGNAL_TRAP",
            const.SEMAPHORE_WAIT_TRAP: "SEMAPHORE_WAIT_TRAP",
            const.KERNELRPC_MACH_PORT_GUARD_TRAP: "KERNELRPC_MACH_PORT_GUARD_TRAP",
            const.MAP_FD_TRAP: "MAP_FD_TRAP",
            const.THREAD_GET_SPECIAL_REPLY_PORT: "THREAD_GET_SPECIAL_REPLY_PORT",
            const.HOST_CREATE_MACH_VOUCHER_TRAP: "HOST_CREATE_MACH_VOUCHER_TRAP",
            const.KERNELRPC_MACH_PORT_TYPE_TRAP: "KERNELRPC_MACH_PORT_TYPE_TRAP",
            const.KERNELRPC_MACH_PORT_REQUEST_NOTIFICATION_TRAP: "KERNELRPC_MACH_PORT_REQUEST_NOTIFICATION_TRAP",
            const.MACH_TIMEBASE_INFO_TRAP: "MACH_TIMEBASE_INFO_TRAP",
            const.MK_TIMER_CREATE_TRAP: "MK_TIMER_CREATE_TRAP",
            const.MK_TIMER_ARM: "MK_TIMER_ARM",
        }

        handlers = {
            const.SYS_SYSCALL: self._handle_sys_syscall,
            const.SYS_EXIT: self._handle_sys_exit,
            const.SYS_FORK: self._handle_sys_fork,
            const.SYS_READ: self._handle_sys_read,
            const.SYS_WRITE: self._handle_sys_write,
            const.SYS_OPEN: self._handle_sys_open,
            const.SYS_CLOSE: self._handle_sys_close,
            const.SYS_LINK: self._handle_sys_link,
            const.SYS_UNLINK: self._handle_sys_unlink,
            const.SYS_CHDIR: self._handle_sys_chdir,
            const.SYS_FCHDIR: self._handle_sys_fchdir,
            const.SYS_CHMOD: self._handle_sys_chmod,
            const.SYS_CHOWN: self._handle_sys_chown,
            const.SYS_GETPID: self._handle_sys_getpid,
            const.SYS_GETUID: self._handle_sys_getuid,
            const.SYS_GETEUID: self._handle_sys_geteuid,
            const.SYS_SENDMSG: self._handle_sys_sendmsg,
            const.SYS_RECVFROM: self._handle_sys_recvfrom,
            const.SYS_GETPEERNAME: self._handle_sys_getpeername,
            const.SYS_GETSOCKNAME: self._handle_sys_getsockname,
            const.SYS_ACCESS: self._handle_sys_access,
            const.SYS_CHFLAGS: self._handle_sys_chflags,
            const.SYS_FCHFLAGS: self._handle_sys_fchflags,
            const.SYS_KILL: self._handle_sys_kill,
            const.SYS_GETPPID: self._handle_sys_getppid,
            const.SYS_DUP: self._handle_sys_dup,
            const.SYS_PIPE: self._handle_sys_pipe,
            const.SYS_SIGACTION: self._handle_sys_sigaction,
            const.SYS_GETGID: self._handle_sys_getgid,
            const.SYS_SIGPROCMASK: self._handle_sys_sigprocmask,
            const.SYS_GETLOGIN: self._handle_sys_getlogin,
            const.SYS_SETLOGIN: self._handle_sys_setlogin,
            const.SYS_SIGALTSTACK: self._handle_sys_sigaltstack,
            const.SYS_IOCTL: self._handle_sys_ioctl,
            const.SYS_REBOOT: self._handle_sys_reboot,
            const.SYS_SYMLINK: self._handle_sys_symlink,
            const.SYS_READLINK: self._handle_sys_readlink,
            const.SYS_MSYNC: self._handle_sys_msync,
            const.SYS_MUNMAP: self._handle_sys_munmap,
            const.SYS_MPROTECT: self._handle_sys_mprotect,
            const.SYS_MADVISE: self._handle_sys_madvise,
            const.SYS_GETEGID: self._handle_sys_getegid,
            const.SYS_GETTIMEOFDAY: self._handle_sys_gettimeofday,
            const.SYS_GETRUSAGE: self._handle_sys_getrusage,
            const.SYS_GETSOCKOPT: self._handle_sys_getsockopt,
            const.SYS_READV: self._handle_sys_readv,
            const.SYS_WRITEV: self._handle_sys_writev,
            const.SYS_FCHOWN: self._handle_sys_fchown,
            const.SYS_FCHMOD: self._handle_sys_fchmod,
            const.SYS_RENAME: self._handle_sys_rename,
            const.SYS_FLOCK: self._handle_sys_flock,
            const.SYS_SENDTO: self._handle_sys_sendto,
            const.SYS_SOCKETPAIR: self._handle_sys_socketpair,
            const.SYS_MKDIR: self._handle_sys_mkdir,
            const.SYS_RMDIR: self._handle_sys_rmdir,
            const.SYS_UTIMES: self._handle_sys_utimes,
            const.SYS_FUTIMES: self._handle_sys_futimes,
            const.SYS_ADJTIME: self._handle_sys_adjtime,
            const.SYS_GETPGID: self._handle_sys_getpgid,
            const.SYS_PREAD: self._handle_sys_pread,
            const.SYS_PWRITE: self._handle_sys_pwrite,
            const.SYS_QUOTACTL: self._handle_sys_quotactl,
            const.SYS_CSOPS: self._handle_sys_csops,
            const.SYS_CSOPS_AUDITTOKEN: self._handle_sys_csops_audittoken,
            const.SYS_GETRLIMIT: self._handle_sys_getrlimit,
            const.SYS_SETRLIMIT: self._handle_sys_setrlimit,
            const.SYS_MMAP: self._handle_sys_mmap,
            const.SYS_LSEEK: self._handle_sys_lseek,
            const.SYS_FSYNC: self._handle_sys_fsync,
            const.SYS_SETPRIORITY: self._handle_sys_setpriority,
            const.SYS_SOCKET: self._handle_sys_socket,
            const.SYS_CONNECT: self._handle_sys_connect,
            const.SYS_GETPRIORITY: self._handle_sys_getpriority,
            const.SYS_BIND: self._handle_sys_bind,
            const.SYS_SETSOCKOPT: self._handle_sys_setsockopt,
            const.SYS_LISTEN: self._handle_sys_listen,
            const.SYS_SIGSUSPEND: self._handle_sys_sigsuspend,
            const.SYS_SETPGID: self._handle_sys_setpgid,
            const.SYS_DUP2: self._handle_sys_dup2,
            const.SYS_FCNTL: self._handle_sys_fcntl,
            const.SYS_SELECT: self._handle_sys_select,
            const.SYS_FTRUNCATE: self._handle_sys_ftruncate,
            const.SYS_SYSCTL: self._handle_sys_sysctl,
            const.SYS_MLOCK: self._handle_sys_mlock,
            const.SYS_MUNLOCK: self._handle_sys_munlock,
            const.SYS_OPEN_DPROTECTED_NP: self._handle_sys_open_dprotected_np,
            const.SYS_GETATTRLIST: self._handle_sys_getattrlist,
            const.SYS_SETXATTR: self._handle_sys_setxattr,
            const.SYS_FSETXATTR: self._handle_sys_fsetxattr,
            const.SYS_LISTXATTR: self._handle_sys_listxattr,
            const.SYS_SHM_OPEN: self._handle_sys_shm_open,
            const.SYS_SYSCTLBYNAME: self._handle_sys_sysctlbyname,
            const.SYS_GETTID: self._handle_sys_gettid,
            const.SYS_IDENTITYSVC: self._handle_sys_identitysvc,
            const.SYS_PSYNCH_MUTEXWAIT: self._handle_sys_psynch_mutexwait,
            const.SYS_PROCESS_POLICY: self._handle_sys_process_policy,
            const.SYS_ISSETUGID: self._handle_sys_issetugid,
            const.SYS_PTHREAD_SIGMASK: self._handle_sys_pthread_sigmask,
            const.SYS_SEMWAIT_SIGNAL: self._handle_sys_semwait_signal,
            const.SYS_PROC_INFO: self._handle_sys_proc_info,
            const.SYS_STAT64: self._handle_sys_stat64,
            const.SYS_FSTAT64: self._handle_sys_fstat64,
            const.SYS_LSTAT64: self._handle_sys_lstat64,
            const.SYS_GETDIRENTRIES64: self._handle_sys_getdirentries64,
            const.SYS_STATFS64: self._handle_sys_statfs64,
            const.SYS_FSTATFS64: self._handle_sys_fstatfs64,
            const.SYS_FSSTAT64: self._handle_sys_fsstat64,
            const.SYS_BSDTHREAD_CREATE: self._handle_sys_bsdthread_create,
            const.SYS_KQUEUE: self._handle_sys_kqueue,
            const.SYS_KEVENT: self._handle_sys_kevent,
            const.SYS_LCHOWN: self._handle_sys_lchown,
            const.SYS_WORKQ_OPEN: self._handle_sys_workq_open,
            const.SYS_WORKQ_KERNRETURN: self._handle_sys_workq_kernreturn,
            const.SYS_THREAD_SELFID: self._handle_sys_thread_selfid,
            const.SYS_KEVENT_QOS: self._handle_sys_kevent_qos,
            const.SYS_KEVENT_ID: self._handle_sys_kevent_id,
            const.SYS_MAC_SYSCALL: self._handle_sys_mac_syscall,
            const.SYS_READ_NOCANCEL: self._handle_sys_read,
            const.SYS_WRITE_NOCANCEL: self._handle_sys_write,
            const.SYS_OPEN_NOCANCEL: self._handle_sys_open,
            const.SYS_CLOSE_NOCANCEL: self._handle_sys_close,
            const.SYS_SENDMSG_NOCANCEL: self._handle_sys_sendmsg,
            const.SYS_RECVFROM_NOCANCEL: self._handle_sys_recvfrom,
            const.SYS_FCNTL_NOCANCEL: self._handle_sys_fcntl,
            const.SYS_SELECT_NOCANCEL: self._handle_sys_select,
            const.SYS_FSYNC_NOCANCEL: self._handle_sys_fsync,
            const.SYS_CONNECT_NOCANCEL: self._handle_sys_connect,
            const.SYS_READV_NOCANCEL: self._handle_sys_readv,
            const.SYS_WRITEV_NOCANCEL: self._handle_sys_writev,
            const.SYS_SENDTO_NOCANCEL: self._handle_sys_sendto,
            const.SYS_PREAD_NOCANCEL: self._handle_sys_pread,
            const.SYS_PWRITE_NOCANCEL: self._handle_sys_pwrite,
            const.SYS_SEMWAIT_SIGNAL_NOCANCEL: self._handle_sys_semwait_signal,
            const.SYS_GUARDED_OPEN_NP: self._handle_sys_guarded_open_np,
            const.SYS_GUARDED_CLOSE_NP: self._handle_sys_guarded_close_np,
            const.SYS_GETATTRLISTBULK: self._handle_sys_getattrlistbulk,
            const.SYS_CLONEFILEAT: self._handle_sys_clonefileat,
            const.SYS_OPENAT: self._handle_sys_openat,
            const.SYS_OPENAT_NOCANCEL: self._handle_sys_openat,
            const.SYS_RENAMEAT: self._handle_sys_renameat,
            const.SYS_FACCESSAT: self._handle_sys_faccessat,
            const.SYS_FCHMODAT: self._handle_sys_fchmodat,
            const.SYS_FCHOWNAT: self._handle_sys_fchownat,
            const.SYS_FSTATAT64: self._handle_sys_fstatat64,
            const.SYS_LINKAT: self._handle_sys_linkat,
            const.SYS_UNLINKAT: self._handle_sys_unlinkat,
            const.SYS_READLINKAT: self._handle_sys_readlinkat,
            const.SYS_SYMLINKAT: self._handle_sys_symlinkat,
            const.SYS_MKDIRAT: self._handle_sys_mkdirat,
            const.SYS_BSDTHREAD_CTL: self._handle_sys_bsdthread_ctl,
            const.SYS_GUARDED_PWRITE_NP: self._handle_sys_guarded_pwrite_np,
            const.SYS_PERSONA: self._handle_sys_persona,
            const.SYS_GETENTROPY: self._handle_sys_getentropy,
            const.SYS_NECP_OPEN: self._handle_sys_necp_open,
            const.SYS_ULOCK_WAIT: self._handle_sys_ulock_wait,
            const.SYS_TERMINATE_WITH_PAYLOAD: self._handle_sys_terminate_with_payload,
            const.SYS_ABORT_WITH_PAYLOAD: self._handle_sys_abort_with_payload,
            const.SYS_OS_FAULT_WITH_PAYLOAD: self._handle_sys_os_fault_with_payload,
            const.SYS_PREADV: self._handle_sys_preadv,
            const.SYS_PREADV_NOCANCEL: self._handle_sys_preadv,
            const.MACH_ABSOLUTE_TIME_TRAP: self._handle_mach_absolute_time_trap,
            const.KERNELRPC_MACH_VM_ALLOCATE_TRAP: self._handle_kernelrpc_mach_vm_allocate_trap,
            const.KERNELRPC_MACH_VM_PURGABLE_CONTROL_TRAP: self._handle_kernelrpc_mach_vm_purgable_control_trap,
            const.KERNELRPC_MACH_VM_DEALLOCATE_TRAP: self._handle_kernelrpc_mach_vm_deallocate_trap,
            const.KERNELRPC_MACH_VM_PROTECT_TRAP: self._handle_kernelrpc_mach_vm_protect_trap,
            const.KERNELRPC_MACH_VM_MAP_TRAP: self._handle_kernelrpc_mach_vm_map_trap,
            const.KERNELRPC_MACH_PORT_ALLOCATE_TRAP: self._handle_kernelrpc_mach_port_allocate_trap,
            const.KERNELRPC_MACH_PORT_DEALLOCATE_TRAP: self._handle_kernelrpc_mach_port_deallocate_trap,
            const.KERNELRPC_MACH_PORT_MOD_REFS_TRAP: self._handle_kernelrpc_mach_port_mod_refs_trap,
            const.KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP: self._handle_kernelrpc_mach_port_insert_member_trap,
            const.KERNELRPC_MACH_PORT_CONSTRUCT_TRAP: self._handle_kernelrpc_mach_port_construct_trap,
            const.KERNELRPC_MACH_PORT_DESTRUCT_TRAP: self._handle_kernelrpc_mach_port_destruct_trap,
            const.MACH_REPLY_PORT_TRAP: self._handle_mach_reply_port_trap,
            const.THREAD_SELF_TRAP: self._handle_thread_self_trap,
            const.TASK_SELF_TRAP: self._handle_task_self_trap,
            const.HOST_SELF_TRAP: self._handle_host_self_trap,
            const.MACH_MSG_TRAP: self._handle_mach_msg_trap,
            const.SEMAPHORE_SIGNAL_TRAP: self._handle_semaphore_signal_trap,
            const.SEMAPHORE_WAIT_TRAP: self._handle_semaphore_wait_trap,
            const.KERNELRPC_MACH_PORT_GUARD_TRAP: self._handle_kernelrpc_mach_port_guard_trap,
            const.MAP_FD_TRAP: self._handle_map_fd_trap,
            const.THREAD_GET_SPECIAL_REPLY_PORT: self._handle_thread_get_special_reply_port,
            const.HOST_CREATE_MACH_VOUCHER_TRAP: self._handle_host_create_mach_voucher_trap,
            const.KERNELRPC_MACH_PORT_TYPE_TRAP: self._handle_kernelrpc_mach_port_type_trap,
            const.KERNELRPC_MACH_PORT_REQUEST_NOTIFICATION_TRAP: self._handle_kernelrpc_mach_port_request_notification_trap,
            const.MACH_TIMEBASE_INFO_TRAP: self._handle_mach_timebase_info_trap,
            const.MK_TIMER_CREATE_TRAP: self._handle_mk_timer_create_trap,
            const.MK_TIMER_ARM: self._handle_mk_timer_arm,
        }

        self._names.update(names)
        self._handlers.update(handlers)

    def _syscall_wrapper(self, handler: Callable):
        retval = -1
        error_type = None

        try:
            retval = handler()
        except (FileNotFoundError, PermissionError):
            error_type = SyscallError.ENOENT
        except FileExistsError:
            error_type = SyscallError.EEXIST
        except UnicodeDecodeError:
            error_type = SyscallError.EPERM
        except OSError:
            error_type = SyscallError.EINVAL
        except SystemOperationFailed as e:
            error_type = e.error_type

        if error_type in SYSCALL_ERRORS:
            error_no, error_name = SYSCALL_ERRORS[error_type]

            self.emu.logger.info(f"Set errno {error_name}({error_no})")
            self.emu.os.set_errno(error_no)
        else:
            self.emu.os.set_errno(0)

        # Clear the carry flag after called, many functions will
        # check it after system calls.
        nzcv = self.emu.uc.reg_read(arm64_const.UC_ARM64_REG_NZCV)
        self.emu.uc.reg_write(arm64_const.UC_ARM64_REG_NZCV, nzcv & ~(1 << 29))

        return retval

    def _handle_sys_syscall(self):
        syscall_no = self.emu.get_arg(0)

        args = []
        for index in range(7):
            args.append(self.emu.get_arg(1 + index))

        for index, arg in enumerate(args):
            self.emu.set_arg(index, arg)

        self.handle_syscall(syscall_no)

    def _handle_sys_exit(self):
        status = self.emu.get_arg(0)

        raise ProgramTerminated("Program terminated with status: %s" % status)

    def _handle_sys_fork(self):
        self.emu.os.raise_permission_denied()

        return 0

    def _handle_sys_read(self):
        fd = self.emu.get_arg(0)
        buf = self.emu.get_arg(1)
        size = self.emu.get_arg(2)

        data = self.emu.os.read(fd, size)
        self.emu.write_bytes(buf, data)

        return len(data)

    def _handle_sys_write(self):
        fd = self.emu.get_arg(0)
        buf = self.emu.get_arg(1)
        size = self.emu.get_arg(2)

        return self.emu.os.write(fd, buf, size)

    def _handle_sys_open(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        flags = self.emu.get_arg(1)
        mode = self.emu.get_arg(2)

        return self.emu.os.open(path, flags, mode)

    def _handle_sys_close(self):
        fd = self.emu.get_arg(0)

        self.emu.os.close(fd)

        return 0

    def _handle_sys_link(self):
        src_path = self.emu.read_string(self.emu.get_arg(0))
        dst_path = self.emu.read_string(self.emu.get_arg(1))

        self.emu.os.link(src_path, dst_path)

        return 0

    def _handle_sys_unlink(self):
        path = self.emu.read_string(self.emu.get_arg(0))

        self.emu.os.unlink(path)

        return 0

    def _handle_sys_chdir(self):
        path = self.emu.read_string(self.emu.get_arg(0))

        self.emu.os.chdir(path)

        return 0

    def _handle_sys_fchdir(self):
        fd = self.emu.get_arg(0)

        self.emu.os.fchdir(fd)

        return 0

    def _handle_sys_chmod(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        mode = self.emu.get_arg(1)

        self.emu.os.chmod(path, mode)

        return 0

    def _handle_sys_chown(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        uid = self.emu.get_arg(1)
        gid = self.emu.get_arg(2)

        self.emu.os.chown(path, uid, gid)

        return 0

    def _handle_sys_getpid(self):
        return self.emu.os.getpid()

    def _handle_sys_getuid(self):
        return self.emu.os.getuid()

    def _handle_sys_geteuid(self):
        return self.emu.os.getuid()

    def _handle_sys_sendmsg(self):
        sock = self.emu.get_arg(0)
        buffer = self.emu.get_arg(1)
        flags = self.emu.get_arg(2)

        return self.emu.os.sendmsg(sock, buffer, flags)

    def _handle_sys_recvfrom(self):
        sock = self.emu.get_arg(0)
        buffer = self.emu.get_arg(1)
        length = self.emu.get_arg(2)
        flags = self.emu.get_arg(3)
        address = self.emu.get_arg(4)
        address_len = self.emu.get_arg(5)

        return self.emu.os.recvfrom(sock, buffer, length, flags, address, address_len)

    def _handle_sys_getpeername(self):
        sock = self.emu.get_arg(0)
        address = self.emu.get_arg(1)

        result = self.emu.os.getpeername(sock)
        if address and result:
            self.emu.write_bytes(address, result)

        return 0

    def _handle_sys_getsockname(self):
        sock = self.emu.get_arg(0)
        address = self.emu.get_arg(1)

        result = self.emu.os.getsockname(sock)
        if address and result:
            self.emu.write_bytes(address, result)

        return 0

    def _handle_sys_access(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        mode = self.emu.get_arg(1)

        if not self.emu.os.access(path, mode):
            return -1

        return 0

    def _handle_sys_chflags(self):
        self.emu.os.raise_permission_denied()

        return 0

    def _handle_sys_fchflags(self):
        self.emu.os.raise_permission_denied()

        return 0

    @staticmethod
    def _handle_sys_kill():
        return -1

    @staticmethod
    def _handle_sys_getppid():
        return 1

    def _handle_sys_dup(self):
        fd = self.emu.get_arg(0)

        return self.emu.os.dup(fd)

    @staticmethod
    def _handle_sys_pipe():
        return -1

    @staticmethod
    def _handle_sys_sigaction():
        return 0

    def _handle_sys_getgid(self):
        return self.emu.os.getgid()

    @staticmethod
    def _handle_sys_sigprocmask():
        return 0

    def _handle_sys_getlogin(self):
        return self.emu.create_const_string("mobile")

    def _handle_sys_setlogin(self):
        self.emu.os.raise_permission_denied()

        return 0

    @staticmethod
    def _handle_sys_sigaltstack():
        return 0

    def _handle_sys_ioctl(self):
        fd = self.emu.get_arg(0)
        req = self.emu.get_arg(1)

        inout = req & ~((0x3FFF << 16) | 0xFF00 | 0xFF)
        group = (req >> 8) & 0xFF
        num = req & 0xFF
        length = (req >> 16) & 0x3FFF

        self.emu.logger.info(
            f"Received an ioctl request: fd={fd}, inout={hex(inout)}, "
            f"group='{chr(group)}', num={num}, length={length}"
        )

        self.emu.logger.warning("ioctl request not processed")
        return 0

    def _handle_sys_reboot(self):
        self.emu.os.raise_permission_denied()

        return 0

    def _handle_sys_symlink(self):
        src_path = self.emu.read_string(self.emu.get_arg(0))
        dst_path = self.emu.read_string(self.emu.get_arg(1))

        self.emu.os.symlink(src_path, dst_path)

        return 0

    def _handle_sys_readlink(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        buf = self.emu.get_arg(1)
        buf_size = self.emu.get_arg(2)

        result = self.emu.os.readlink(path)
        if result is None or len(result) > buf_size:
            return -1

        self.emu.write_string(buf, result)

        return 0

    def _handle_sys_msync(self):
        addr = self.emu.get_arg(0)
        length = self.emu.get_arg(1)

        self.emu.os.msync(addr, length)

        return 0

    def _handle_sys_munmap(self):
        addr = self.emu.get_arg(0)

        self.emu.os.munmap(addr)

        return 0

    @staticmethod
    def _handle_sys_mprotect():
        return 0

    @staticmethod
    def _handle_sys_madvise():
        return 0

    def _handle_sys_getegid(self):
        return self.emu.os.getgid()

    def _handle_sys_gettimeofday(self):
        tv = self.emu.get_arg(0)

        result = self.emu.os.gettimeofday()
        self.emu.write_bytes(tv, result)

        return 0

    def _handle_sys_getrusage(self):
        r = self.emu.get_arg(1)

        rusage = Rusage()
        self.emu.write_bytes(r, struct_to_bytes(rusage))

        return 0

    def _handle_sys_getsockopt(self):
        sock = self.emu.get_arg(0)
        level = self.emu.get_arg(1)
        option_name = self.emu.get_arg(2)
        option_value = self.emu.get_arg(3)
        option_len = self.emu.get_arg(4)

        return self.emu.os.getsockopt(
            sock, level, option_name, option_value, option_len
        )

    def _handle_sys_readv(self):
        fd = self.emu.get_arg(0)
        iov = self.emu.get_arg(1)
        iovcnt = self.emu.get_arg(2)

        result = 0

        for _ in range(iovcnt):
            iov_base = self.emu.read_pointer(iov)
            iov_len = self.emu.read_u64(iov + 8)

            data = self.emu.os.read(fd, iov_len)
            self.emu.write_bytes(iov_base, data)

            result += len(data)

            if len(data) != iov_len:
                break

            iov += 16

        return result

    def _handle_sys_writev(self):
        fd = self.emu.get_arg(0)
        iov = self.emu.get_arg(1)
        iovcnt = self.emu.get_arg(2)

        result = 0

        for _ in range(iovcnt):
            iov_base = self.emu.read_pointer(iov)
            iov_len = self.emu.read_u64(iov + 8)

            write_len = self.emu.os.write(fd, iov_base, iov_len)
            result += write_len

            if write_len != iov_len:
                break

            iov += 16

        return result

    def _handle_sys_fchown(self):
        fd = self.emu.get_arg(0)
        uid = self.emu.get_arg(1)
        gid = self.emu.get_arg(2)

        self.emu.os.fchown(fd, uid, gid)

        return 0

    def _handle_sys_fchmod(self):
        fd = self.emu.get_arg(0)
        mode = self.emu.get_arg(1)

        self.emu.os.fchmod(fd, mode)

        return 0

    def _handle_sys_rename(self):
        old = self.emu.read_string(self.emu.get_arg(0))
        new = self.emu.read_string(self.emu.get_arg(1))

        self.emu.os.rename(old, new)

        return 0

    @staticmethod
    def _handle_sys_flock():
        pass

    def _handle_sys_sendto(self):
        sock = self.emu.get_arg(0)
        buffer = self.emu.get_arg(1)
        length = self.emu.get_arg(2)
        flags = self.emu.get_arg(3)
        dest_addr = self.emu.get_arg(4)
        dest_len = self.emu.get_arg(5)

        return self.emu.os.sendto(sock, buffer, length, flags, dest_addr, dest_len)

    def _handle_sys_socketpair(self):
        domain = self.emu.get_arg(0)
        sock_type = self.emu.get_arg(1)
        protocol = self.emu.get_arg(2)
        socket_vector = self.emu.get_arg(3)

        result = self.emu.os.socketpair(domain, sock_type, protocol)
        if not result:
            return -1

        self.emu.write_s32(socket_vector, result[0])
        self.emu.write_s32(socket_vector + 4, result[1])

        return 0

    def _handle_sys_mkdir(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        mode = self.emu.get_arg(1)

        self.emu.os.mkdir(path, mode)

        return 0

    def _handle_sys_rmdir(self):
        path = self.emu.read_string(self.emu.get_arg(0))

        self.emu.os.rmdir(path)

        return 0

    def _handle_sys_utimes(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        times_ptr = self.emu.get_arg(1)

        if times_ptr:
            time1 = read_struct(self.emu, times_ptr, Timespec)
            time2 = read_struct(self.emu, times_ptr + ctypes.sizeof(Timespec), Timespec)
            times = (time1.to_seconds(), time2.to_seconds())
        else:
            times = None

        self.emu.os.utimes(path, times)

        return 0

    def _handle_sys_futimes(self):
        fd = self.emu.get_arg(0)
        times_ptr = self.emu.get_arg(1)

        if times_ptr:
            time1 = read_struct(self.emu, times_ptr, Timespec)
            time2 = read_struct(self.emu, times_ptr + ctypes.sizeof(Timespec), Timespec)
            times = (time1.to_seconds(), time2.to_seconds())
        else:
            times = None

        self.emu.os.futimes(fd, times)

        return 0

    def _handle_sys_adjtime(self):
        self.emu.os.raise_permission_denied()

        return 0

    def _handle_sys_getpgid(self):
        pid = self.emu.get_arg(0)

        if pid == 0 or pid == self.emu.os.getpid():
            return self.emu.os.getpgid()
        elif pid == 1:
            return 1

        self.emu.os.raise_permission_denied()

        return 0

    def _handle_sys_pread(self):
        fd = self.emu.get_arg(0)
        buf = self.emu.get_arg(1)
        size = self.emu.get_arg(2)
        offset = self.emu.get_arg(3)

        data = self.emu.os.pread(fd, size, offset)
        self.emu.write_bytes(buf, data)

        return len(data)

    def _handle_sys_pwrite(self):
        fd = self.emu.get_arg(0)
        buf = self.emu.get_arg(1)
        size = self.emu.get_arg(2)
        offset = self.emu.get_arg(3)

        return self.emu.os.pwrite(fd, buf, size, offset)

    @staticmethod
    def _handle_sys_quotactl():
        return 0

    def _handle_sys_csops(self):
        useraddr = self.emu.get_arg(2)

        flags = 0

        flags |= 0x00000800

        flags |= 0x00000300

        self.emu.write_u32(useraddr, flags)

        return 0

    @staticmethod
    def _handle_sys_csops_audittoken():
        return 0

    def _handle_sys_getrlimit(self):
        resource = self.emu.get_arg(0)
        rlp = self.emu.get_arg(1)

        resource &= ~0x1000

        if resource not in RESOURCE_LIMITS:
            raise SystemOperationFailed("Invalid value", SyscallError.EINVAL)

        rlim_cur, rlim_max = RESOURCE_LIMITS[resource]

        rlimit = Rlimit(
            rlim_cur=rlim_cur,
            rlim_max=rlim_max,
        )

        if rlp:
            self.emu.write_bytes(rlp, struct_to_bytes(rlimit))

        return 0

    def _handle_sys_setrlimit(self):
        self.emu.os.raise_permission_denied()

        return 0

    def _handle_sys_mmap(self):
        length = self.emu.get_arg(1)
        fd = to_signed(self.emu.get_arg(4), 4)
        offset = self.emu.get_arg(5)

        return self.emu.os.mmap(length, fd, offset)

    def _handle_sys_lseek(self):
        fd = self.emu.get_arg(0)
        offset = self.emu.get_arg(1)
        whence = self.emu.get_arg(2)

        offset = to_signed(offset, 8)

        return self.emu.os.lseek(fd, offset, whence)

    def _handle_sys_fsync(self):
        fd = self.emu.get_arg(0)

        self.emu.os.fsync(fd)

        return 0

    def _handle_sys_setpriority(self):
        self.emu.os.raise_permission_denied()

        return 0

    def _handle_sys_socket(self):
        domain = self.emu.get_arg(0)
        sock_type = self.emu.get_arg(1)
        protocol = self.emu.get_arg(2)

        return self.emu.os.socket(domain, sock_type, protocol)

    def _handle_sys_connect(self):
        sock = self.emu.get_arg(0)
        address = self.emu.get_arg(1)
        address_len = self.emu.get_arg(2)

        return self.emu.os.connect(sock, address, address_len)

    @staticmethod
    def _handle_sys_getpriority():
        return 0

    def _handle_sys_bind(self):
        sock = self.emu.get_arg(0)
        address = self.emu.get_arg(1)
        address_len = self.emu.get_arg(2)

        return self.emu.os.bind(sock, address, address_len)

    def _handle_sys_setsockopt(self):
        sock = self.emu.get_arg(0)
        level = self.emu.get_arg(1)
        option_name = self.emu.get_arg(2)
        option_value = self.emu.get_arg(3)
        option_len = self.emu.get_arg(4)

        return self.emu.os.setsockopt(
            sock, level, option_name, option_value, option_len
        )

    def _handle_sys_listen(self):
        sock = self.emu.get_arg(0)
        backlog = self.emu.get_arg(1)

        return self.emu.os.listen(sock, backlog)

    @staticmethod
    def _handle_sys_sigsuspend():
        return -1

    def _handle_sys_setpgid(self):
        self.emu.os.raise_permission_denied()

        return 0

    def _handle_sys_dup2(self):
        old_fd = self.emu.get_arg(0)
        new_fd = self.emu.get_arg(1)

        self.emu.os.dup2(old_fd, new_fd)

        return 0

    def _handle_sys_fcntl(self):
        fd = self.emu.get_arg(0)
        cmd = self.emu.get_arg(1)
        arg = self.emu.get_arg(2)

        return self.emu.os.fcntl(fd, cmd, arg)

    def _handle_sys_select(self):
        nfds = self.emu.get_arg(0)
        readfds = self.emu.get_arg(1)
        writefds = self.emu.get_arg(2)
        errorfds = self.emu.get_arg(3)
        timeout = self.emu.get_arg(4)

        return self.emu.os.select(nfds, readfds, writefds, errorfds, timeout)

    def _handle_sys_ftruncate(self):
        fd = self.emu.get_arg(0)
        length = self.emu.get_arg(1)

        self.emu.os.ftruncate(fd, length)

        return 0

    def _handle_sys_sysctl(self):
        name = self.emu.get_arg(0)
        oldp = self.emu.get_arg(2)
        oldlenp = self.emu.get_arg(3)

        mib = (
            self.emu.read_u32(name),
            self.emu.read_u32(name + 4),
            self.emu.read_u32(name + 8),
            self.emu.read_u32(name + 12),
            self.emu.read_u32(name + 16),
            self.emu.read_u32(name + 20),
        )

        result = sysctl(mib)
        if result is None:
            self.emu.logger.warning(f"Unhandled sysctl command: {mib}")
            return -1

        if oldp:
            if isinstance(result, ctypes.Structure):
                self.emu.write_bytes(oldp, struct_to_bytes(result))
            elif isinstance(result, str):
                self.emu.write_string(oldp, result)
            elif isinstance(result, bytes):
                self.emu.write_bytes(oldp, result)
            elif isinstance(result, int):
                self.emu.write_u64(oldp, result)
            elif isinstance(result, list):
                offset = 0
                for st in result:
                    self.emu.write_bytes(oldp + offset, struct_to_bytes(st))
                    offset += ctypes.sizeof(st)

        if oldlenp:
            if isinstance(result, ctypes.Structure):
                self.emu.write_u32(oldlenp, ctypes.sizeof(result))
            elif isinstance(result, str):
                self.emu.write_u32(oldlenp, len(result))
            elif isinstance(result, bytes):
                self.emu.write_u32(oldlenp, len(result))
            elif isinstance(result, int):
                self.emu.write_u32(oldlenp, 8)
            elif isinstance(result, list):
                result_len = 0
                for st in result:
                    result_len += ctypes.sizeof(st)
                self.emu.write_u32(oldlenp, result_len)

        return 0

    def _handle_sys_mlock(self):
        addr = self.emu.get_arg(0)
        length = self.emu.get_arg(1)

        self.emu.os.mlock(addr, length)

        return 0

    def _handle_sys_munlock(self):
        addr = self.emu.get_arg(0)
        length = self.emu.get_arg(1)

        self.emu.os.munlock(addr, length)

        return 0

    def _handle_sys_open_dprotected_np(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        flags = self.emu.get_arg(1)
        mode = self.emu.get_arg(4)

        return self.emu.os.open(path, flags, mode)

    @staticmethod
    def _handle_sys_getattrlist():
        return -1

    @staticmethod
    def _handle_sys_setxattr():
        return 0

    @staticmethod
    def _handle_sys_fsetxattr():
        return 0

    @staticmethod
    def _handle_sys_listxattr():
        return 0

    @staticmethod
    def _handle_sys_shm_open():
        return 0x80000000

    def _handle_sys_sysctlbyname(self):
        name = self.emu.read_string(self.emu.get_arg(0))
        oldp = self.emu.get_arg(2)
        oldlenp = self.emu.get_arg(3)

        result = sysctlbyname(name)
        if result is None:
            self.emu.logger.warning(f"Unhandled sysctl command: {name}")
            return -1

        if oldp:
            if isinstance(result, ctypes.Structure):
                self.emu.write_bytes(oldp, struct_to_bytes(result))
            elif isinstance(result, str):
                self.emu.write_string(oldp, result)
            elif isinstance(result, int):
                self.emu.write_u64(oldp, result)

        if oldlenp:
            if isinstance(result, ctypes.Structure):
                self.emu.write_u32(oldlenp, ctypes.sizeof(result))
            elif isinstance(result, str):
                self.emu.write_u32(oldlenp, len(result))
            elif isinstance(result, int):
                self.emu.write_u32(oldlenp, 8)

        return 0

    def _handle_sys_gettid(self):
        return self.emu.os.gettid()

    def _handle_sys_identitysvc(self):
        self.emu.os.raise_permission_denied()

        return 0

    @staticmethod
    def _handle_sys_psynch_mutexwait():
        return 0

    @staticmethod
    def _handle_sys_process_policy():
        return 0

    @staticmethod
    def _handle_sys_issetugid():
        return 0

    @staticmethod
    def _handle_sys_pthread_sigmask():
        return 0

    def _handle_sys_semwait_signal(self):
        raise SystemOperationFailed("Wait signal", SyscallError.ETIMEDOUT)

    def _handle_sys_proc_info(self):
        pid = self.emu.get_arg(1)
        flavor = self.emu.get_arg(2)
        buffer = self.emu.get_arg(4)

        if pid != self.emu.os.getpid():
            self.emu.os.raise_permission_denied()

        self.emu.logger.info(f"pid={pid}, flavor={flavor}")

        if flavor == const.PROC_PIDTBSDINFO:
            bsd_info = ProcBsdinfo(
                pbi_pid=self.emu.os.getpid(),
                pbi_ppid=1,
                pbi_uid=self.emu.os.getuid(),
                pbi_gid=self.emu.os.getgid(),
            )
            result = struct_to_bytes(bsd_info)
        elif flavor == const.PROC_PIDPATHINFO:
            self.emu.write_string(buffer, self.emu.ios_os.executable_path)
            result = self.emu.ios_os.executable_path.encode("utf-8")
        elif flavor == const.PROC_PIDT_SHORTBSDINFO:
            bsd_short_info = ProcBsdshortinfo(
                pbsi_pid=self.emu.os.getpid(),
                pbsi_ppid=1,
                pbsi_uid=self.emu.os.getuid(),
                pbsi_gid=self.emu.os.getgid(),
            )
            result = struct_to_bytes(bsd_short_info)
        elif flavor == const.PROC_PIDUNIQIDENTIFIERINFO:
            uniq_identifier_info = ProcUniqidentifierinfo()
            result = struct_to_bytes(uniq_identifier_info)
        else:
            self.emu.logger.warning("Unhandled proc_info call")
            return 0

        self.emu.write_bytes(buffer, result)
        return len(result)

    def _handle_sys_stat64(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        stat = self.emu.get_arg(1)

        self.emu.write_bytes(stat, self.emu.os.stat(path))

        return 0

    def _handle_sys_fstat64(self):
        fd = self.emu.get_arg(0)
        stat = self.emu.get_arg(1)

        self.emu.write_bytes(stat, self.emu.os.fstat(fd))

        return 0

    def _handle_sys_lstat64(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        stat = self.emu.get_arg(1)

        self.emu.write_bytes(stat, self.emu.os.lstat(path))

        return 0

    def _handle_sys_getdirentries64(self):
        fd = self.emu.get_arg(0)
        buf = self.emu.get_arg(1)
        nbytes = self.emu.get_arg(2)
        basep = self.emu.get_arg(3)

        base = self.emu.read_u64(basep)

        result = self.emu.ios_os.getdirentries(fd, base)
        if result is None:
            return 0

        if nbytes < len(result):
            return 0

        self.emu.write_bytes(buf, result[:nbytes])
        self.emu.write_u64(basep, base + 1)

        return len(result)

    def _handle_sys_statfs64(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        statfs = self.emu.get_arg(1)

        self.emu.write_bytes(statfs, self.emu.os.statfs(path))

        return 0

    def _handle_sys_fstatfs64(self):
        fd = self.emu.get_arg(0)
        statfs = self.emu.get_arg(1)

        self.emu.write_bytes(statfs, self.emu.os.fstatfs(fd))

        return 0

    def _handle_sys_fsstat64(self):
        statfs = self.emu.get_arg(0)
        if not statfs:
            return 1

        self.emu.write_bytes(statfs, self.emu.os.statfs("/"))

        return 0

    def _handle_sys_bsdthread_create(self):
        self.emu.logger.warning("Emulator ignored a thread create reqeust.")
        self.emu.log_backtrace()

        return 0

    def _handle_sys_kqueue(self):
        return self.emu.ios_os.kqueue()

    def _handle_sys_kevent(self):
        kq = self.emu.get_arg(0)
        change_ptr = self.emu.get_arg(1)
        n_changes = self.emu.get_arg(2)
        event_ptr = self.emu.get_arg(3)
        n_event = self.emu.get_arg(4)
        timeout = self.emu.get_arg(5)

        return self.emu.ios_os.kevent(
            kq,
            change_ptr,
            n_changes,
            event_ptr,
            n_event,
            timeout,
        )

    def _handle_sys_lchown(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        uid = self.emu.get_arg(1)
        gid = self.emu.get_arg(2)

        self.emu.os.lchown(path, uid, gid)

        return 0

    @staticmethod
    def _handle_sys_workq_open():
        return 0

    @staticmethod
    def _handle_sys_workq_kernreturn():
        return 0

    def _handle_sys_thread_selfid(self):
        return self.emu.os.gettid()

    @staticmethod
    def _handle_sys_kevent_qos():
        return 0

    @staticmethod
    def _handle_sys_kevent_id():
        return 0

    def _handle_sys_mac_syscall(self):
        cmd = self.emu.read_string(self.emu.get_arg(0))
        self.emu.logger.info(f"Received a mac syscall command: {cmd}")

        if cmd == "Sandbox":
            pass
        else:
            self.emu.logger.warning(f"Unhandled mac syscall command: {cmd}")

        return 0

    def _handle_sys_guarded_open_np(self):
        path = self.emu.read_string(self.emu.get_arg(0))
        flags = self.emu.get_arg(3)
        mode = self.emu.get_arg(4)

        return self.emu.os.open(path, flags, mode)

    def _handle_sys_guarded_close_np(self):
        fd = self.emu.get_arg(0)

        self.emu.os.close(fd)

        return 0

    @staticmethod
    def _handle_sys_getattrlistbulk():
        return 0

    def _handle_sys_clonefileat(self):
        src_dir_fd = to_signed(self.emu.get_arg(0), 4)
        src_path = self.emu.read_string(self.emu.get_arg(1))
        dst_dir_fd = to_signed(self.emu.get_arg(2), 4)
        dst_path = self.emu.read_string(self.emu.get_arg(3))

        self.emu.ios_os.clonefileat(src_dir_fd, src_path, dst_dir_fd, dst_path)

        return 0

    def _handle_sys_openat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        flags = self.emu.get_arg(2)
        mode = self.emu.get_arg(3)

        return self.emu.os.openat(dir_fd, path, flags, mode)

    def _handle_sys_renameat(self):
        src_fd = self.emu.get_arg(0)
        old = self.emu.read_string(self.emu.get_arg(1))
        dst_fd = self.emu.get_arg(2)
        new = self.emu.read_string(self.emu.get_arg(3))

        self.emu.os.renameat(src_fd, old, dst_fd, new)

        return 0

    def _handle_sys_faccessat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        mode = self.emu.get_arg(2)

        if not self.emu.os.faccessat(dir_fd, path, mode):
            return -1

        return 0

    def _handle_sys_fchmodat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        mode = self.emu.get_arg(2)

        self.emu.os.fchmodat(dir_fd, path, mode)

        return 0

    def _handle_sys_fchownat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        uid = self.emu.get_arg(2)
        gid = self.emu.get_arg(3)

        self.emu.os.fchownat(dir_fd, path, uid, gid)

        return 0

    def _handle_sys_fstatat64(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        stat = self.emu.get_arg(2)

        self.emu.write_bytes(stat, self.emu.os.fstatat(dir_fd, path))

        return 0

    def _handle_sys_linkat(self):
        src_dir_fd = to_signed(self.emu.get_arg(0), 4)
        src_path = self.emu.read_string(self.emu.get_arg(1))
        dst_dir_fd = to_signed(self.emu.get_arg(2), 4)
        dst_path = self.emu.read_string(self.emu.get_arg(3))

        self.emu.os.linkat(src_dir_fd, src_path, dst_dir_fd, dst_path)

        return 0

    def _handle_sys_unlinkat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))

        self.emu.os.unlinkat(dir_fd, path)

        return 0

    def _handle_sys_readlinkat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))

        self.emu.os.readlinkat(dir_fd, path)

        return 0

    def _handle_sys_symlinkat(self):
        src_dir_fd = to_signed(self.emu.get_arg(0), 4)
        src_path = self.emu.read_string(self.emu.get_arg(1))
        dst_dir_fd = to_signed(self.emu.get_arg(2), 4)
        dst_path = self.emu.read_string(self.emu.get_arg(3))

        self.emu.os.symlinkat(src_dir_fd, src_path, dst_dir_fd, dst_path)

        return 0

    def _handle_sys_mkdirat(self):
        dir_fd = to_signed(self.emu.get_arg(0), 4)
        path = self.emu.read_string(self.emu.get_arg(1))
        mode = self.emu.get_arg(2)

        self.emu.os.mkdirat(dir_fd, path, mode)

        return 0

    @staticmethod
    def _handle_sys_bsdthread_ctl():
        return 0

    def _handle_sys_guarded_pwrite_np(self):
        fd = self.emu.get_arg(0)
        buf = self.emu.get_arg(2)
        size = self.emu.get_arg(3)
        offset = self.emu.get_arg(4)

        return self.emu.os.pwrite(fd, buf, size, offset)

    @staticmethod
    def _handle_sys_persona():
        return 0

    def _handle_sys_getentropy(self):
        buffer = self.emu.get_arg(0)
        size = self.emu.get_arg(1)

        rand_bytes = bytes([random.randint(0, 255) for _ in range(size)])
        self.emu.write_bytes(buffer, rand_bytes)

        return 0

    @staticmethod
    def _handle_sys_necp_open():
        return -1

    @staticmethod
    def _handle_sys_ulock_wait():
        return 0

    def _handle_sys_terminate_with_payload(self):
        payload = self.emu.get_arg(5)
        msg = self.emu.read_string(payload)

        self.emu.log_backtrace()

        raise ProgramTerminated("terminate with payload: %s" % msg)

    def _handle_sys_abort_with_payload(self):
        payload = self.emu.get_arg(4)
        msg = self.emu.read_string(payload)

        self.emu.log_backtrace()

        raise ProgramTerminated("abort with payload: %s" % msg)

    def _handle_sys_os_fault_with_payload(self):
        payload = self.emu.get_arg(2)
        msg = self.emu.read_string(payload)

        self.emu.log_backtrace()

        raise ProgramTerminated("OS fault with payload: %s" % msg)

    def _handle_sys_preadv(self):
        fd = self.emu.get_arg(0)
        iov = self.emu.get_arg(1)
        iovcnt = self.emu.get_arg(2)
        offset = self.emu.get_arg(3)

        pos = self.emu.os.lseek(fd, 0, os.SEEK_CUR)
        self.emu.os.lseek(fd, offset, os.SEEK_SET)

        result = 0

        for _ in range(iovcnt):
            iov_base = self.emu.read_pointer(iov)
            iov_len = self.emu.read_u64(iov + 8)

            data = self.emu.os.read(fd, iov_len)
            self.emu.write_bytes(iov_base, data)

            result += len(data)

            if len(data) != iov_len:
                break

            iov += 16

        self.emu.os.lseek(fd, pos, os.SEEK_SET)

        return result

    @staticmethod
    def _handle_mach_absolute_time_trap():
        return int(time.time_ns() % (3600 * 10**9))

    def _handle_kernelrpc_mach_vm_allocate_trap(self):
        address = self.emu.get_arg(1)
        size = self.emu.get_arg(2)

        mem = self.emu.memory_manager.alloc(size)
        self.emu.write_bytes(mem, bytes(size))

        self.emu.write_pointer(address, mem)

        return 0

    @staticmethod
    def _handle_kernelrpc_mach_vm_purgable_control_trap():
        return 0

    def _handle_kernelrpc_mach_vm_deallocate_trap(self):
        mem = self.emu.get_arg(1)

        self.emu.memory_manager.free(mem)

        return 0

    @staticmethod
    def _handle_kernelrpc_mach_vm_protect_trap():
        return 0

    def _handle_kernelrpc_mach_vm_map_trap(self):
        address = self.emu.get_arg(1)
        size = self.emu.get_arg(2)

        mem = self.emu.memory_manager.alloc(size)
        self.emu.write_pointer(address, mem)

        return 0

    def _handle_kernelrpc_mach_port_allocate_trap(self):
        name = self.emu.get_arg(2)

        port = self.emu.ios_os.mach_port_construct()
        self.emu.write_u32(name, port)

        return 0

    def _handle_kernelrpc_mach_port_deallocate_trap(self):
        name = self.emu.get_arg(1)

        self.emu.ios_os.mach_port_destruct(name)

        return 0

    @staticmethod
    def _handle_kernelrpc_mach_port_mod_refs_trap():
        return 0

    @staticmethod
    def _handle_kernelrpc_mach_port_insert_member_trap():
        return 0

    def _handle_kernelrpc_mach_port_construct_trap(self):
        name = self.emu.get_arg(3)

        port = self.emu.ios_os.mach_port_construct()
        self.emu.write_u32(name, port)

        return 0

    def _handle_kernelrpc_mach_port_destruct_trap(self):
        name = self.emu.get_arg(1)

        self.emu.ios_os.mach_port_destruct(name)

        return 0

    def _handle_mach_reply_port_trap(self):
        return self.emu.ios_os.MACH_PORT_REPLY

    def _handle_thread_self_trap(self):
        return self.emu.ios_os.MACH_PORT_THREAD

    def _handle_task_self_trap(self):
        return self.emu.ios_os.MACH_PORT_TASK

    def _handle_host_self_trap(self):
        return self.emu.ios_os.MACH_PORT_HOST

    def _handle_mach_msg_trap(self):
        msg = self.emu.get_arg(0)
        option = self.emu.get_arg(1)
        send_size = self.emu.get_arg(2)
        rcv_size = self.emu.get_arg(3)
        rcv_name = self.emu.get_arg(4)
        timeout = self.emu.get_arg(5)
        notify = self.emu.get_arg(6)

        return self.emu.ios_os.mach_msg(
            msg,
            option,
            send_size,
            rcv_size,
            rcv_name,
            timeout,
            notify,
        )

    def _handle_semaphore_signal_trap(self):
        semaphore = self.emu.get_arg(0)
        return self.emu.ios_os.semaphore_signal(semaphore)

    def _handle_semaphore_wait_trap(self):
        semaphore = self.emu.get_arg(0)

        self.emu.logger.info("Waiting semaphore...")
        return self.emu.ios_os.semaphore_wait(semaphore)

    @staticmethod
    def _handle_kernelrpc_mach_port_guard_trap():
        return 0

    def _handle_map_fd_trap(self):
        activity_id = self.emu.get_arg(2)

        self.emu.write_u64(activity_id, random.getrandbits(64))

        return 0

    def _handle_thread_get_special_reply_port(self):
        return self.emu.ios_os.MACH_PORT_REPLY

    @staticmethod
    def _handle_host_create_mach_voucher_trap():
        return 0

    def _handle_kernelrpc_mach_port_type_trap(self):
        ptype = self.emu.get_arg(2)

        value = 0
        value |= const.MACH_PORT_TYPE_SEND
        value |= const.MACH_PORT_TYPE_RECEIVE

        self.emu.write_u32(ptype, value)

        return 0

    @staticmethod
    def _handle_kernelrpc_mach_port_request_notification_trap():
        return 0

    def _handle_mach_timebase_info_trap(self):
        info = self.emu.get_arg(0)

        self.emu.write_u32(info, 1)
        self.emu.write_u32(info + 4, 1)

        return 0

    def _handle_mk_timer_create_trap(self):
        return self.emu.ios_os.MACH_PORT_TIMER

    @staticmethod
    def _handle_mk_timer_arm():
        return 0
