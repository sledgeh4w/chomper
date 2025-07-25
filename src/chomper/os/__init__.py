from .base import BaseOs
from .android import AndroidOs
from .android.syscall import get_syscall_name as android_get_syscall_name
from .ios import IosOs
from .ios.syscall import get_syscall_name as ios_get_syscall_name
