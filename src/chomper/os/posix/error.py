from enum import Enum


class SyscallError(Enum):
    EPERM = 1
    ENOENT = 2
    EBADF = 3
    EACCES = 4
    EFAULT = 5
    EEXIST = 6
    ENOTDIR = 7
    EINVAL = 8
    EMFILE = 9
    ETIMEDOUT = 10
