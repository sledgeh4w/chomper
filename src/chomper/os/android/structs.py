import ctypes


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


class Stat64(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_int64),
        ("st_ino", ctypes.c_uint64),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_int32),
        ("__pad1", ctypes.c_uint64),
        ("st_size", ctypes.c_int64),
        ("st_blksize", ctypes.c_int32),
        ("__pad2", ctypes.c_int32),
        ("st_blocks", ctypes.c_int64),
        ("st_atim", Timespec),
        ("st_mtim", Timespec),
        ("st_ctim", Timespec),
    ]


class Statfs64(ctypes.Structure):
    _fields_ = [
        ("f_type", ctypes.c_int32),
        ("f_bsize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_uint64),
        ("f_namelen", ctypes.c_int32),
        ("f_frsize", ctypes.c_int32),
        ("f_flags", ctypes.c_int32),
        ("f_spare", ctypes.c_int32 * 4),
    ]


class Dirent(ctypes.Structure):
    _fields_ = [
        ("d_ino", ctypes.c_uint64),
        ("d_seekoff", ctypes.c_uint64),
        ("d_reclen", ctypes.c_uint16),
        ("d_type", ctypes.c_uint8),
        ("d_name", ctypes.c_char * 256),
    ]
