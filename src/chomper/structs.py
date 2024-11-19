from ctypes import Structure, c_int32, c_int64, c_uint16, c_uint32, c_uint64


class MachHeader64(Structure):
    _fields_ = [
        ("magic", c_uint32),
        ("cputype", c_uint32),
        ("cpusubtype", c_uint32),
        ("filetype", c_uint32),
        ("ncmds", c_uint32),
        ("sizeofcmds", c_uint32),
        ("flags", c_uint32),
        ("reserved", c_uint32),
    ]


class Timespec(Structure):
    _fields_ = [
        ("tv_sec", c_int64),
        ("tv_nsec", c_int64),
    ]

    @classmethod
    def from_time_ns(cls, time_ns: int) -> "Timespec":
        """Create a Timespec structure from nanoseconds."""
        return cls(
            tv_sec=time_ns // (10**9),
            tv_nsec=time_ns % (10**9),
        )


class Stat(Structure):
    _fields_ = [
        ("st_dev", c_int32),
        ("st_ino", c_uint32),
        ("st_mode", c_uint16),
        ("st_nlink", c_uint16),
        ("st_uid", c_uint32),
        ("st_gid", c_uint32),
        ("st_rdev", c_int32),
        ("st_atimespec", Timespec),
        ("st_mtimespec", Timespec),
        ("st_ctimespec", Timespec),
        ("st_size", c_int64),
        ("st_blocks", c_int64),
        ("st_blksize", c_int32),
        ("st_flags", c_uint32),
        ("st_gen", c_uint32),
        ("st_lspare", c_int32),
        ("st_qspare", c_int64 * 2),
    ]


class Stat64(Structure):
    _fields_ = [
        ("st_dev", c_int32),
        ("st_mode", c_uint16),
        ("st_nlink", c_uint16),
        ("st_ino", c_uint64),
        ("st_uid", c_uint32),
        ("st_gid", c_uint32),
        ("st_rdev", c_int32),
        ("st_atimespec", Timespec),
        ("st_mtimespec", Timespec),
        ("st_ctimespec", Timespec),
        ("st_birthtimespec", Timespec),
        ("st_size", c_int64),
        ("st_blocks", c_int64),
        ("st_blksize", c_int32),
        ("st_flags", c_uint32),
        ("st_gen", c_uint32),
        ("st_lspare", c_int32),
        ("st_qspare", c_int64 * 2),
    ]
