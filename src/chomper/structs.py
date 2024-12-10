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
        """Create a Timespec structure from nanoseconds."""
        return cls(
            tv_sec=time_ns // (10**9),
            tv_nsec=time_ns % (10**9),
        )


class Stat(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_int32),
        ("st_ino", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint16),
        ("st_nlink", ctypes.c_uint16),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_int32),
        ("st_atimespec", Timespec),
        ("st_mtimespec", Timespec),
        ("st_ctimespec", Timespec),
        ("st_size", ctypes.c_int64),
        ("st_blocks", ctypes.c_int64),
        ("st_blksize", ctypes.c_int32),
        ("st_flags", ctypes.c_uint32),
        ("st_gen", ctypes.c_uint32),
        ("st_lspare", ctypes.c_int32),
        ("st_qspare", ctypes.c_int64 * 2),
    ]


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


class Dirent(ctypes.Structure):
    _fields_ = [
        ("d_ino", ctypes.c_uint64),
        ("d_seekoff", ctypes.c_uint64),
        ("d_reclen", ctypes.c_uint16),
        ("d_namlen", ctypes.c_uint16),
        ("d_type", ctypes.c_uint8),
        ("d_name", ctypes.c_char * 1024),
    ]
