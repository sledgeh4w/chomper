from ctypes import Structure, c_uint32


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
