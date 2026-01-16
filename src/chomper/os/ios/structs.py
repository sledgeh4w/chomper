import ctypes


class MachHeader64(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("cputype", ctypes.c_uint32),
        ("cpusubtype", ctypes.c_uint32),
        ("filetype", ctypes.c_uint32),
        ("ncmds", ctypes.c_uint32),
        ("sizeofcmds", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


class Timespec(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_int64),
        ("tv_nsec", ctypes.c_int64),
    ]

    @classmethod
    def from_time_ns(cls, time_ns: int) -> "Timespec":
        return cls(
            tv_sec=time_ns // (10**9),
            tv_nsec=time_ns % (10**9),
        )

    def to_seconds(self) -> float:
        return float(self.tv_sec) + float(self.tv_nsec) / 1e9


class Stat64(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_int32),
        ("st_mode", ctypes.c_uint16),
        ("st_nlink", ctypes.c_uint16),
        ("st_ino", ctypes.c_uint64),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_int32),
        ("st_atimespec", Timespec),
        ("st_mtimespec", Timespec),
        ("st_ctimespec", Timespec),
        ("st_birthtimespec", Timespec),
        ("st_size", ctypes.c_int64),
        ("st_blocks", ctypes.c_int64),
        ("st_blksize", ctypes.c_int32),
        ("st_flags", ctypes.c_uint32),
        ("st_gen", ctypes.c_uint32),
        ("st_lspare", ctypes.c_int32),
        ("st_qspare", ctypes.c_int64 * 2),
    ]


class Statfs64(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_uint64),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_reserved", ctypes.c_uint32 * 8),
    ]


class Statvfs64(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint64),
        ("f_frsize", ctypes.c_uint64),
        ("f_blocks", ctypes.c_uint32),
        ("f_bfree", ctypes.c_uint32),
        ("f_bavail", ctypes.c_uint32),
        ("f_files", ctypes.c_uint32),
        ("f_ffree", ctypes.c_uint32),
        ("f_favail", ctypes.c_uint32),
        ("f_fsid", ctypes.c_uint64),
        ("f_flag", ctypes.c_uint64),
        ("f_namemax", ctypes.c_uint64),
    ]


class Dirent(ctypes.Structure):
    _fields_ = [
        ("d_ino", ctypes.c_uint64),
        ("d_seekoff", ctypes.c_uint64),
        ("d_reclen", ctypes.c_uint16),
        ("d_namlen", ctypes.c_uint16),
        ("d_type", ctypes.c_uint8),
        ("d_name", ctypes.c_char * 1024),
    ]


class Timeval(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_int64),
        ("tv_usec", ctypes.c_int32),
    ]


class Rusage(ctypes.Structure):
    _fields_ = [
        ("ru_utime", Timeval),
        ("ru_stime", Timeval),
        ("ru_maxrss", ctypes.c_int64),
        ("ru_ixrss", ctypes.c_int64),
        ("ru_idrss", ctypes.c_int64),
        ("ru_isrss", ctypes.c_int64),
        ("ru_minflt", ctypes.c_int64),
        ("ru_majflt", ctypes.c_int64),
        ("ru_nswap", ctypes.c_int64),
        ("ru_inblock", ctypes.c_int64),
        ("ru_oublock", ctypes.c_int64),
        ("ru_msgsnd", ctypes.c_int64),
        ("ru_msgrcv", ctypes.c_int64),
        ("ru_nsignals", ctypes.c_int64),
        ("ru_nvcsw", ctypes.c_int64),
        ("ru_nivcsw", ctypes.c_int64),
    ]


class SockaddrUn(ctypes.Structure):
    _fields_ = [
        ("sun_len", ctypes.c_uint8),
        ("sun_family", ctypes.c_uint8),
        ("sun_path", ctypes.c_char * 104),
    ]


class SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_len", ctypes.c_uint8),
        ("sin_family", ctypes.c_uint8),
        ("sin_port", ctypes.c_uint16),
        ("sin_addr", ctypes.c_uint32),
        ("sin_zero", ctypes.c_char * 8),
    ]


class ProcBsdinfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


class ProcBsdshortinfo(ctypes.Structure):
    _fields_ = [
        ("pbsi_pid", ctypes.c_uint32),
        ("pbsi_ppid", ctypes.c_uint32),
        ("pbsi_pgid", ctypes.c_uint32),
        ("pbsi_status", ctypes.c_uint32),
        ("pbsi_comm", ctypes.c_char * 16),
        ("pbsi_flags", ctypes.c_uint32),
        ("pbsi_uid", ctypes.c_uint32),
        ("pbsi_gid", ctypes.c_uint32),
        ("pbsi_ruid", ctypes.c_uint32),
        ("pbsi_rgid", ctypes.c_uint32),
        ("pbsi_svuid", ctypes.c_uint32),
        ("pbsi_svgid", ctypes.c_uint32),
        ("pbsi_rfu", ctypes.c_uint32),
    ]


class ProcUniqidentifierinfo(ctypes.Structure):
    _fields_ = [
        ("p_uuid", ctypes.c_uint8 * 16),
        ("p_uniqueid", ctypes.c_uint64),
        ("p_puniqueid", ctypes.c_uint64),
        ("p_idversion", ctypes.c_int32),
        ("p_orig_ppidversion", ctypes.c_int32),
        ("p_reserve2", ctypes.c_uint64),
        ("p_reserve3", ctypes.c_uint64),
    ]


class MachMsgHeader(ctypes.Structure):
    _fields_ = [
        ("msgh_bits", ctypes.c_uint32),
        ("msgh_size", ctypes.c_uint32),
        ("msgh_remote_port", ctypes.c_uint32),
        ("msgh_local_port", ctypes.c_uint32),
        ("msgh_voucher_port", ctypes.c_uint32),
        ("msgh_id", ctypes.c_int32),
    ]


class MachMsgBody(ctypes.Structure):
    _fields_ = [
        ("msgh_descriptor_count", ctypes.c_uint32),
    ]


class MachMsgTypeDescriptor(ctypes.Structure):
    _fields_ = [
        ("pad1", ctypes.c_uint32),
        ("pad1", ctypes.c_uint32),
        ("pad1", ctypes.c_int, 24),
        ("type", ctypes.c_uint8),
    ]


class MachMsgPortDescriptor(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_uint32),
        ("pad1", ctypes.c_uint32),
        ("pad2", ctypes.c_uint16),
        ("disposition", ctypes.c_uint8),
        ("type", ctypes.c_uint8),
    ]


class MachMsgOolDescriptor(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_uint64),
        ("deallocate", ctypes.c_uint8),
        ("copy", ctypes.c_uint8),
        ("disposition", ctypes.c_uint8),
        ("type", ctypes.c_uint8),
        ("size", ctypes.c_uint32),
    ]


class MachMsgOolPortsDescriptor(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_uint64),
        ("deallocate", ctypes.c_uint8),
        ("copy", ctypes.c_uint8),
        ("disposition", ctypes.c_uint8),
        ("type", ctypes.c_uint8),
        ("count", ctypes.c_uint32),
    ]


class MachMsgGuardedPortDescriptor(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_uint64),
        ("flags", ctypes.c_uint16),
        ("disposition", ctypes.c_uint8),
        ("type", ctypes.c_uint8),
        ("name", ctypes.c_uint32),
    ]


class MachTimespec(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_uint32),
        ("tv_nsec", ctypes.c_int32),
    ]

    @classmethod
    def from_time_ns(cls, time_ns: int) -> "MachTimespec":
        return cls(
            tv_sec=time_ns // (10**9),
            tv_nsec=time_ns % (10**9),
        )


class VmRegionBasicInfo64(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("protection", ctypes.c_int32),
        ("max_protection", ctypes.c_int32),
        ("inheritance", ctypes.c_uint32),
        ("shared", ctypes.c_int32),
        ("reserved", ctypes.c_int32),
        ("offset", ctypes.c_uint64),
        ("behavior", ctypes.c_int32),
        ("user_wired_count", ctypes.c_uint16),
    ]


class HostBasicInfo(ctypes.Structure):
    _fields_ = [
        ("max_cpus", ctypes.c_int32),
        ("avail_cpus", ctypes.c_int32),
        ("memory_size", ctypes.c_uint32),
        ("cpu_type", ctypes.c_int32),
        ("cpu_subtype", ctypes.c_int32),
        ("cpu_threadtype", ctypes.c_int32),
        ("physical_cpu", ctypes.c_int32),
        ("physical_cpu_max", ctypes.c_int32),
        ("logical_cpu", ctypes.c_int32),
        ("logical_cpu_max", ctypes.c_int32),
        ("max_mem", ctypes.c_uint64),
    ]


class VmStatistics(ctypes.Structure):
    _fields_ = [
        ("free_count", ctypes.c_uint32),
        ("active_count", ctypes.c_uint32),
        ("inactive_count", ctypes.c_uint32),
        ("wire_count", ctypes.c_uint32),
        ("zero_fill_count", ctypes.c_uint32),
        ("reactivations", ctypes.c_uint32),
        ("pageins", ctypes.c_uint32),
        ("pageouts", ctypes.c_uint32),
        ("faults", ctypes.c_uint32),
        ("cow_faults", ctypes.c_uint32),
        ("lookups", ctypes.c_uint32),
        ("hits", ctypes.c_uint32),
        ("purgeable_count", ctypes.c_uint32),
        ("purges", ctypes.c_uint32),
        ("speculative_count", ctypes.c_uint32),
    ]


class VmStatistics64(ctypes.Structure):
    _fields_ = [
        ("free_count", ctypes.c_uint32),
        ("active_count", ctypes.c_uint32),
        ("inactive_count", ctypes.c_uint32),
        ("wire_count", ctypes.c_uint32),
        ("zero_fill_count", ctypes.c_uint64),
        ("reactivations", ctypes.c_uint64),
        ("pageins", ctypes.c_uint64),
        ("pageouts", ctypes.c_uint64),
        ("faults", ctypes.c_uint64),
        ("cow_faults", ctypes.c_uint64),
        ("lookups", ctypes.c_uint64),
        ("hits", ctypes.c_uint64),
        ("purges", ctypes.c_uint64),
        ("purgeable_count", ctypes.c_uint32),
        ("speculative_count", ctypes.c_uint32),
        ("decompressions", ctypes.c_uint64),
        ("compressions", ctypes.c_uint64),
        ("swapins", ctypes.c_uint64),
        ("swapouts", ctypes.c_uint64),
        ("compressor_page_count", ctypes.c_uint32),
        ("throttled_count", ctypes.c_uint32),
        ("external_page_count", ctypes.c_uint32),
        ("internal_page_count", ctypes.c_uint32),
        ("total_uncompressed_pages_in_compressor", ctypes.c_uint64),
    ]


class DlInfo(ctypes.Structure):
    _fields_ = [
        ("dli_fname", ctypes.c_uint64),
        ("dli_fbase", ctypes.c_uint64),
        ("dli_sname", ctypes.c_uint64),
        ("dli_saddr", ctypes.c_uint64),
    ]


class Utsname(ctypes.Structure):
    _fields_ = [
        ("sysname", ctypes.c_char * 256),
        ("nodename", ctypes.c_char * 256),
        ("release", ctypes.c_char * 256),
        ("version", ctypes.c_char * 256),
        ("machine", ctypes.c_char * 256),
    ]


class Rlimit(ctypes.Structure):
    _fields_ = [
        ("rlim_cur", ctypes.c_uint64),
        ("rlim_max", ctypes.c_uint64),
    ]
