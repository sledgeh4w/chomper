import ctypes
import os
import plistlib
import random
import shutil
import socket
import sys
import time
import uuid
from typing import List, Optional

from chomper.const import STACK_ADDRESS, STACK_SIZE, TLS_ADDRESS
from chomper.exceptions import EmulatorCrashed, SystemOperationFailed
from chomper.loader import MachoLoader, Module
from chomper.os.device import NullDevice, RandomDevice, UrandomDevice
from chomper.os.posix import PosixOs, SyscallError
from chomper.os.handle import HandleManager
from chomper.utils import log_call, struct_to_bytes, to_unsigned

from .fixup import SystemModuleFixer
from .hooks import get_hooks
from .mach import MachMsgHandler
from .structs import Dirent, Stat64, Statfs64, Timespec, SockaddrIn
from .syscall import get_syscall_handlers, get_syscall_names
from .xpc import XpcMessageHandler


ENVIRON_VARIABLES = r"""SHELL=/bin/sh
PWD=/var/root
LOGNAME=root
HOME=/var/root
LS_COLORS=rs=0:di=01
CLICOLOR=
SSH_CONNECTION=127.0.0.1 59540 127.0.0.1 22
TERM=xterm
USER=root
SHLVL=1
PS1=\h:\w \u\$
SSH_CLIENT=127.0.0.1 59540 22
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/X11:/usr/games
MAIL=/var/mail/root
SSH_TTY=/dev/ttys000
_=/usr/bin/env
SBUS_INSERT_LIBRARIES=/usr/lib/substitute-inserter.dylib
__CF_USER_TEXT_ENCODING=0x0:0:0
CFN_USE_HTTP3=0
CFStringDisableROM=1"""

# System libraries and frameworks to load
SYSTEM_MODULES = [
    "/usr/lib/system/libsystem_kernel.dylib",
    "/usr/lib/system/libsystem_platform.dylib",
    "/usr/lib/system/libsystem_c.dylib",
    "/usr/lib/system/libsystem_featureflags.dylib",
    "/usr/lib/system/libsystem_pthread.dylib",
    "/usr/lib/libc++abi.dylib",
    "/usr/lib/libc++.1.dylib",
    "/usr/lib/system/libmacho.dylib",
    "/usr/lib/system/libdyld.dylib",
    "/usr/lib/libobjc.A.dylib",
    "/usr/lib/system/libcache.dylib",
    "/usr/lib/system/libcorecrypto.dylib",
    "/usr/lib/system/libcommonCrypto.dylib",
    "/usr/lib/system/libcompiler_rt.dylib",
    "/usr/lib/system/libdispatch.dylib",
    "/usr/lib/system/libremovefile.dylib",
    "/usr/lib/system/libsystem_blocks.dylib",
    "/usr/lib/system/libsystem_configuration.dylib",
    "/usr/lib/system/libsystem_coreservices.dylib",
    "/usr/lib/system/libsystem_darwin.dylib",
    "/usr/lib/system/libsystem_info.dylib",
    "/usr/lib/system/libsystem_networkextension.dylib",
    "/usr/lib/system/libsystem_notify.dylib",
    "/usr/lib/system/libsystem_m.dylib",
    "/usr/lib/system/libsystem_sandbox.dylib",
    "/usr/lib/system/libsystem_trace.dylib",
    "/usr/lib/system/libxpc.dylib",
    "/usr/lib/libAccessibility.dylib",
    "/usr/lib/libbsm.0.dylib",
    "/usr/lib/libcupolicy.dylib",
    "/usr/lib/libicucore.A.dylib",
    "/usr/lib/libnetwork.dylib",
    "/usr/lib/libMobileGestalt.dylib",
    "/usr/lib/libresolv.9.dylib",
    "/usr/lib/libTelephonyUtilDynamic.dylib",
    "/usr/lib/libz.1.dylib",
    "/System/Library/Frameworks/CoreFoundation",
    "/System/Library/Frameworks/Foundation",
    "/System/Library/Frameworks/CFNetwork",
    "/System/Library/Frameworks/CoreGraphics",
    "/System/Library/Frameworks/CoreLocation",
    "/System/Library/Frameworks/CoreServices",
    "/System/Library/Frameworks/CoreTelephony",
    "/System/Library/Frameworks/CoreText",
    "/System/Library/Frameworks/IOKit",
    "/System/Library/Frameworks/QuartzCore",
    "/System/Library/Frameworks/Security",
    "/System/Library/Frameworks/SystemConfiguration",
    "/System/Library/PrivateFrameworks/BackBoardServices",
    "/System/Library/PrivateFrameworks/BaseBoard",
    "/System/Library/PrivateFrameworks/BoardServices",
    "/System/Library/PrivateFrameworks/CoreAutoLayout",
    "/System/Library/PrivateFrameworks/CoreServicesStore",
    "/System/Library/PrivateFrameworks/FontServices.framework/libGSFont.dylib",
    "/System/Library/PrivateFrameworks/FontServices.framework/libGSFontCache.dylib",
    "/System/Library/PrivateFrameworks/FrontBoardServices",
    "/System/Library/PrivateFrameworks/MobileKeyBag",
    "/System/Library/PrivateFrameworks/PhysicsKit",
    "/System/Library/PrivateFrameworks/PrototypeTools",
    "/System/Library/PrivateFrameworks/RunningBoardServices",
    "/System/Library/PrivateFrameworks/TextInput",
    "/System/Library/PrivateFrameworks/UIFoundation",
    "/System/Library/PrivateFrameworks/UIKitCore",
    "/System/Library/PrivateFrameworks/UIKitServices",
]

# Symbolic links in the file system
SYMBOLIC_LINKS = {
    "/etc": "/private/etc",
    "/tmp": "/private/var/tmp",
    "/var": "/private/var",
    "/usr/share/zoneinfo": "/var/db/timezone/zoneinfo",
    "/var/db/timezone/icutz": "/var/db/timezone/tz/2024a.1.0/icutz/",
    "/var/db/timezone/localtime": "/var/db/timezone/zoneinfo/Asia/Shanghai",
    "/var/db/timezone/tz_latest": " /var/db/timezone/tz/2024a.1.0/",
    "/var/db/timezone/zoneinfo": "/var/db/timezone/tz/2024a.1.0/zoneinfo/",
}

# Default bundle values until an executable with Info.plist is loaded
BUNDLE_UUID = "00000000-0000-0000-0000-000000000000"
BUNDLE_IDENTIFIER = "com.sh4w.chomper"
BUNDLE_EXECUTABLE = "Chomper"

PREFERENCES = {
    "AppleLanguages": [
        "zh-Hans",
        "en",
    ],
    "AppleLocale": "zh-Hans",
}

# Virtual device files
DEVICES_FILES = {
    "/dev/null": NullDevice,
    "/dev/random": RandomDevice,
    "/dev/urandom": UrandomDevice,
}


class IosOs(PosixOs):
    """Provide iOS environment."""

    AT_FDCWD = to_unsigned(-2, size=4)

    MACH_PORT_NULL = 0
    MACH_PORT_HOST = 1
    MACH_PORT_TASK = 2
    MACH_PORT_THREAD = 3
    MACH_PORT_BOOTSTRAP = 4
    MACH_PORT_REPLY = 5
    MACH_PORT_CLOCK = 6
    MACH_PORT_IO_MASTER = 7
    MACH_PORT_DEBUG_CONTROL = 8

    MACH_PORT_TIMER = 256

    MACH_PORT_NOTIFICATION_CENTER = 4096
    MACH_PORT_CA_RENDER_SERVER = 4097
    MACH_PORT_ADVERTISING_IDENTIFIERS = 4098
    MACH_PORT_BKS_HID_SERVER = 4099
    MACH_PORT_CONFIGD = 4100

    MACH_PORT_START_VALUE = 65536
    MACH_PORT_MAX_NUM = 10000

    MACH_SERVICES = {
        "com.apple.system.notification_center": MACH_PORT_NOTIFICATION_CENTER,
        "com.apple.CARenderServer": MACH_PORT_CA_RENDER_SERVER,
        "com.apple.lsd.advertisingidentifiers": MACH_PORT_ADVERTISING_IDENTIFIERS,
        "com.apple.backboard.hid.services": MACH_PORT_BKS_HID_SERVER,
        "com.apple.SystemConfiguration.configd": MACH_PORT_CONFIGD,
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.loader = MachoLoader(self.emu)

        # mobile user
        self.uid = 501
        self.gid = self.uid

        self.pid = random.randint(1000, 2000)
        self.pgid = self.pid

        self.tid = random.randint(10000, 20000)

        self.executable_path = (
            f"/private/var/containers/Bundle/Application"
            f"/{BUNDLE_UUID}"
            f"/{BUNDLE_IDENTIFIER}"
            f"/{BUNDLE_EXECUTABLE}"
        )
        self.executable_file = ""

        self.preferences = PREFERENCES.copy()

        # Semaphore
        self._semaphore_map = {}
        self._semaphore_queue = {}

        # Mach port
        self._mach_port_manager = HandleManager(
            start_value=self.MACH_PORT_START_VALUE,
            max_num=self.MACH_PORT_MAX_NUM,
        )

        self._mach_services = {}

        # Mach msg
        self._mach_msg_handler = MachMsgHandler(self.emu, self._mach_port_manager)

        # Xpc message
        self._xpc_message_handler = XpcMessageHandler(self.emu)

    def get_errno(self) -> int:
        """Get the `errno`."""
        errno = self.emu.get_symbol("_errno")
        return self.emu.read_s32(errno.address)

    def set_errno(self, value: int):
        """Set the `errno`."""
        errno = self.emu.get_symbol("_errno")
        self.emu.write_s32(errno.address, value)

        errno_ptr = self.emu.read_pointer(TLS_ADDRESS + 0x8)
        self.emu.write_s32(errno_ptr, value)

    @staticmethod
    def _construct_stat(st: os.stat_result) -> bytes:
        if sys.platform == "win32":
            block_size = 4096

            rdev = 0
            blocks = st.st_size // (block_size // 8) + 1
            blksize = block_size
        else:
            rdev = st.st_rdev
            blocks = st.st_blocks
            blksize = st.st_blksize

        if sys.platform == "darwin":
            flags = st.st_flags
        else:
            flags = 0

        atimespec = Timespec.from_time_ns(st.st_atime_ns)
        mtimespec = Timespec.from_time_ns(st.st_mtime_ns)
        ctimespec = Timespec.from_time_ns(st.st_ctime_ns)

        st = Stat64(
            st_dev=st.st_dev,
            st_mode=st.st_mode,
            st_nlink=st.st_nlink,
            st_ino=st.st_ino,
            st_uid=st.st_uid,
            st_gid=st.st_gid,
            st_rdev=rdev,
            st_atimespec=atimespec,
            st_mtimespec=mtimespec,
            st_ctimespec=ctimespec,
            st_size=st.st_size,
            st_blocks=blocks,
            st_blksize=blksize,
            st_flags=flags,
        )

        return struct_to_bytes(st)

    @staticmethod
    def _construct_device_stat() -> bytes:
        atimespec = Timespec.from_time_ns(0)
        mtimespec = Timespec.from_time_ns(0)
        ctimespec = Timespec.from_time_ns(0)

        st = Stat64(
            st_dev=0,
            st_mode=0x2000,
            st_nlink=0,
            st_ino=0,
            st_uid=0,
            st_gid=0,
            st_rdev=0,
            st_atimespec=atimespec,
            st_mtimespec=mtimespec,
            st_ctimespec=ctimespec,
            st_size=0,
            st_blocks=0,
            st_blksize=0,
            st_flags=0,
        )

        return struct_to_bytes(st)

    @staticmethod
    def _construct_statfs() -> bytes:
        st = Statfs64(
            f_bsize=4096,
            f_iosize=1048576,
            f_blocks=31218501,
            f_bfree=29460883,
            f_bavail=25672822,
            f_files=1248740040,
            f_ffree=1248421957,
            f_fsid=103095992327,
            f_owner=0,
            f_type=24,
            f_flags=343986176,
            f_fssubtype=0,
            f_fstypename=b"apfs",
            f_mntonname=b"/",
            f_mntfromname=b"/dev/disk0s1s1",
        )
        return struct_to_bytes(st)

    @classmethod
    def _construct_sockaddr_in(cls, address: str, port: int) -> bytes:
        sa = SockaddrIn(
            sin_len=ctypes.sizeof(SockaddrIn),
            sin_family=cls.AF_INET,
            sin_port=socket.htons(port),
            sin_addr=int.from_bytes(socket.inet_aton(address), "little"),
        )
        return struct_to_bytes(sa)

    @log_call
    def getdirentries(self, fd: int, offset: int) -> Optional[bytes]:
        if not self._is_dir_fd(fd):
            raise SystemOperationFailed(f"Not a directory: {fd}", SyscallError.ENOTDIR)

        path = self._get_fd_path(fd)
        real_path = self._get_real_path(path)

        dir_entries = list(os.scandir(real_path))
        if offset >= len(dir_entries):
            return None

        dir_entry = dir_entries[offset]

        st = Dirent(
            d_ino=dir_entry.inode(),
            d_seekoff=0,
            d_reclen=ctypes.sizeof(Dirent),
            d_namlen=len(dir_entry.name),
            d_type=(4 if dir_entry.is_dir() else 0),
            d_name=dir_entry.name.encode("utf-8"),
        )
        return struct_to_bytes(st)

    @log_call
    def clonefileat(
        self, src_dir_fd: int, src_path: str, dst_dir_fd: int, dst_path: str
    ):
        src_path = self._resolve_dir_fd(src_dir_fd, src_path)
        dst_path = self._resolve_dir_fd(dst_dir_fd, dst_path)

        real_src_path = self._get_real_path(src_path)
        real_dst_path = self._get_real_path(dst_path)

        shutil.copy2(real_src_path, real_dst_path)

    def _setup_tls(self):
        """Initialize thread local storage (TLS)."""
        errno_ptr = self.emu.create_buffer(0x8)

        self.emu.write_pointer(TLS_ADDRESS - 0xE0, TLS_ADDRESS - 0xE0)

        self.emu.write_u64(TLS_ADDRESS - 0x8, self.tid)

        self.emu.write_pointer(TLS_ADDRESS + 0x8, errno_ptr)
        self.emu.write_u32(TLS_ADDRESS + 0x18, 5)

    def _setup_system_registers(self):
        """Initialize MMIO for system registers."""

        def read_cb(uc, offset, size_, read_ud):
            # Arch type
            if offset == 0x23:
                return 0x2
            # vm_page_shift
            elif offset == 0x25:
                return 0xE
            # vm_kernel_page_shift
            elif offset == 0x37:
                return 0xE
            # whether to trace
            elif offset == 0x100:
                return 0x0
            # Unknown, appear at _os_trace_init_slow
            elif offset == 0x104:
                return 0x100

            return 0

        def write_cb(uc, offset, size_, value, write_ud):
            pass

        address = 0xFFFFFC000
        size = 0x1000

        self.emu.uc.mmio_map(address, size, read_cb, None, write_cb, None)

    def _init_lib_dyld(self):
        g_use_dyld3 = self.emu.get_symbol("_gUseDyld3")
        self.emu.write_u8(g_use_dyld3.address, 1)

        dyld_all_images = self.emu.get_symbol("__ZN5dyld310gAllImagesE")

        # dyld3::closure::ContainerTypedBytes::findAttributePayload
        attribute_payload_ptr = self.emu.create_buffer(8)

        self.emu.write_u32(attribute_payload_ptr, 2**10)
        self.emu.write_u8(attribute_payload_ptr + 4, 0x20)

        self.emu.write_pointer(dyld_all_images.address, attribute_payload_ptr)

        # dyld3::AllImages::platform
        platform_ptr = self.emu.create_buffer(0x144)
        self.emu.write_u32(platform_ptr + 0x140, 2)

        self.emu.write_pointer(dyld_all_images.address + 0x50, platform_ptr)

        # environ
        environ_pointer = self.emu.get_symbol("_environ_pointer")
        environ_value = self.emu.read_pointer(environ_pointer.address)

        environ_buf = self.emu.create_buffer(8)
        self.emu.write_pointer(environ_buf, environ_value)

        environ = self.emu.get_symbol("_environ")
        self.emu.write_pointer(environ.address, environ_buf)

    def _init_lib_system_c(self):
        # __program_vars_init
        argc = self.emu.create_buffer(8)
        self.emu.write_int(argc, 0, 8)

        nx_argc_pointer = self.emu.get_symbol("_NXArgc_pointer")
        self.emu.write_pointer(nx_argc_pointer.address, argc)

        nx_argv_pointer = self.emu.get_symbol("_NXArgv_pointer")
        self.emu.write_pointer(nx_argv_pointer.address, self.emu.create_string(""))

        environ = self.emu.create_buffer(8)
        self.emu.write_pointer(environ, self._create_environ(ENVIRON_VARIABLES))

        environ_pointer = self.emu.get_symbol("_environ_pointer")
        self.emu.write_pointer(environ_pointer.address, environ)

        progname = self.emu.create_buffer(8)
        self.emu.write_pointer(progname, self.emu.create_string(BUNDLE_EXECUTABLE))

        progname_pointer = self.emu.get_symbol("___progname_pointer")
        self.emu.write_pointer(progname_pointer.address, progname)

        # ___xlocale_init
        locale_key = self.emu.get_symbol("___locale_key")
        if self.emu.read_s64(locale_key.address) == -1:
            self.emu.write_s64(locale_key.address, 10)

        self.emu.call_symbol("___atexit_init")

        # _init_clock_port
        clock_port = self.emu.get_symbol("_clock_port")
        self.emu.write_u32(clock_port.address, self.MACH_PORT_CLOCK)

    def _init_lib_system_pthread(self):
        main_thread = self.emu.create_buffer(256)

        self.emu.write_pointer(main_thread + 0xB0, STACK_ADDRESS)
        self.emu.write_pointer(main_thread + 0xE0, STACK_ADDRESS + STACK_SIZE)

        main_thread_ptr = self.emu.get_symbol("__main_thread_ptr")
        self.emu.write_pointer(main_thread_ptr.address, main_thread)

        self.emu.write_pointer(main_thread, main_thread)

        pthread_ptr_munge_token = self.emu.get_symbol("__pthread_ptr_munge_token")
        self.emu.write_pointer(pthread_ptr_munge_token.address, 0)

        pthread_supported_features = self.emu.get_symbol(
            "___pthread_supported_features"
        )
        self.emu.write_u32(pthread_supported_features.address, 0x50)

        mach_task_self = self.emu.get_symbol("_mach_task_self_")
        self.emu.write_u32(mach_task_self.address, self.MACH_PORT_TASK)

    def _init_lib_objc(self):
        prototypes = self.emu.get_symbol("__ZL10prototypes")
        self.emu.write_u64(prototypes.address, 0)

        gdb_objc_realized_classes = self.emu.get_symbol("_gdb_objc_realized_classes")
        protocolsv_ret = self.emu.call_symbol("__ZL9protocolsv")

        self.emu.write_pointer(gdb_objc_realized_classes.address, protocolsv_ret)

        opt = self.emu.get_symbol("__ZL3opt")
        self.emu.write_pointer(opt.address, 0)

        # Disable pre-optimization
        disable_preopt = self.emu.get_symbol("_DisablePreopt")
        self.emu.write_u8(disable_preopt.address, 1)

        self.emu.call_symbol("__objc_init")

    def _init_system_symbols(self):
        # libsandbox.dylib
        amkrtemp_sentinel = self.emu.get_symbol("__amkrtemp.sentinel")
        if amkrtemp_sentinel:
            self.emu.write_pointer(
                amkrtemp_sentinel.address,
                self.emu.create_string(""),
            )

        # CoreFoundation
        is_cf_prefs_d = self.emu.get_symbol("_isCFPrefsD")
        if is_cf_prefs_d:
            self.emu.write_u8(is_cf_prefs_d.address, 1)

        # BackBoardServices
        bks_hid_sever_port = self.emu.get_symbol("_BKSHIDServerPort")
        if bks_hid_sever_port:
            self.emu.write_u32(
                bks_hid_sever_port.address,
                self.MACH_PORT_BKS_HID_SERVER,
            )

        # MobileKeyBag
        g_user_unlocked_since_boot = self.emu.get_symbol("_gUserUnlockedSinceBoot")
        if g_user_unlocked_since_boot:
            self.emu.write_u8(g_user_unlocked_since_boot.address, 1)

    def _init_system_module(self, name: str, module: Module):
        """For certain system modules, perform additional initialization before
        and after Objective-C initialization."""
        if name == "libsystem_kernel.dylib":
            self.emu.call_symbol("_mach_init_doit")
        elif name == "libsystem_c.dylib":
            self._init_lib_system_c()
        elif name == "libdyld.dylib":
            self._init_lib_dyld()
        elif name == "libsystem_pthread.dylib":
            self._init_lib_system_pthread()
        elif name == "libsystem_trace.dylib":
            self.emu.call_symbol("__libtrace_init")
        elif name == "libobjc.A.dylib":
            self._init_lib_objc()

        # Initialize Objective-C
        self.init_objc(module)

        if name == "libxpc.dylib":
            self.emu.call_symbol("__libxpc_initializer")
        elif name == "CoreFoundation":
            self._fix_method_signature_rom_table()
            self.emu.call_symbol("___CFInitialize")
        elif name == "Foundation":
            self.emu.call_symbol("__NSInitializePlatform")

    def init_objc(self, module: Module):
        """Initialize Objective-C for the module by calling `map_images`
        and `load_images`.
        """
        if not self.emu.find_module("libobjc.A.dylib"):
            return

        mach_header_ptr = module.macho_info.image_header
        mach_header_ptrs = self.emu.create_buffer(self.emu.arch.addr_size)

        mh_execute_header_pointer = self.emu.get_symbol("__mh_execute_header_pointer")

        self.emu.write_pointer(mach_header_ptrs, mach_header_ptr)
        self.emu.write_pointer(mh_execute_header_pointer.address, mach_header_ptr)

        try:
            self.emu.call_symbol("_map_images", 1, 0, mach_header_ptrs)
            self.emu.call_symbol("_load_images", 0, mach_header_ptr)
        except EmulatorCrashed:
            self.emu.logger.warning("Initialize Objective-C failed.")

            # Release locks
            runtime_lock = self.emu.get_symbol("_runtimeLock")
            self.emu.write_u64(runtime_lock.address, 0)

            lcl_rwlock = self.emu.get_symbol("_lcl_rwlock")
            self.emu.write_u64(lcl_rwlock.address, 0)

    def search_module_binary(self, name: str) -> str:
        """Search system module binary in rootfs directory.

        Args:
            name: The module name.

        Returns:
            Full file path if module found.

        raises:
            FileNotFoundError: If module not found.
        """
        lib_dirs = [
            "usr/lib/system",
            "usr/lib",
            "System/Library/Frameworks",
            "System/Library/PrivateFrameworks",
        ]

        for lib_dir in lib_dirs:
            path = os.path.join(self.rootfs_path or ".", lib_dir)

            lib_path = os.path.join(path, name)
            if os.path.exists(lib_path):
                return lib_path

            framework_path = os.path.join(path, f"{name}.framework")
            if os.path.exists(framework_path):
                return os.path.join(framework_path, name)

        raise FileNotFoundError("Module '%s' not found" % name)

    def resolve_modules(self, paths: List[str]):
        """Load and initialize system modules."""
        for path in paths:
            name = os.path.basename(path)
            if self.emu.find_module(name):
                continue

            module_file = None

            if path.startswith("/"):
                module_file = os.path.join(self.rootfs_path or ".", path[1:])

            if not module_file or not os.path.exists(module_file):
                module_file = self.search_module_binary(name)

            module = self.emu.load_module(
                module_file=module_file,
                exec_objc_init=False,
                exec_init_array=False,
            )

            # Fixup must be executed before initializing Objective-C
            fixer = SystemModuleFixer(self.emu, module)
            fixer.fixup_all()

            # Execute initialization functions after fixup
            if module.init_array:
                init_array = [
                    module.base - module.macho_info.image_base + init_func
                    for init_func in module.init_array
                ]
                self.emu.exec_init_array(init_array)

            self._init_system_module(name, module)

    def _setup_bundle_dir(self):
        """Set bundle directory as current working directory."""
        bundle_path = os.path.dirname(self.executable_path)
        container_path = os.path.dirname(bundle_path)

        self.set_working_dir(bundle_path)

        local_container_path = os.path.join(
            self.rootfs_path,
            "private",
            "var",
            "containers",
            "Bundle",
            "Application",
            BUNDLE_UUID,
        )
        local_bundle_path = os.path.join(local_container_path, BUNDLE_IDENTIFIER)

        self.forward_path(container_path, local_container_path)
        self.forward_path(bundle_path, local_bundle_path)

    def set_executable_file(self, path: str):
        """Set program path and name to global variables while forwarding
        the file access to executable.

        When an `Info.plist` file is located in the same directory as
        the executable, the runtime automatically extracts its `CFBundleIdentifier`
        and `CFBundleExecutable` values.
        """
        self.executable_file = path

        bundle_path = os.path.dirname(self.executable_path)
        container_path = os.path.dirname(bundle_path)

        executable_dir = os.path.dirname(self.executable_file)
        info_path = os.path.join(executable_dir, "Info.plist")

        if os.path.exists(info_path):
            with open(info_path, "rb") as f:
                info_data = plistlib.load(f)

            bundle_identifier = info_data["CFBundleIdentifier"]
            bundle_executable = info_data["CFBundleExecutable"]

            bundle_path = f"{container_path}/{bundle_identifier}"
            self.executable_path = f"{bundle_path}/{bundle_executable}"

            self._setup_bundle_dir()

            progname_str = self.emu.create_string(self.executable_path.split("/")[-1])
            process_path_str = self.emu.create_string(self.executable_path)

            progname = self.emu.create_buffer(8)
            self.emu.write_pointer(progname, progname_str)

            progname_pointer = self.emu.get_symbol("___progname_pointer")
            self.emu.write_pointer(progname_pointer.address, progname)

            cf_progname = self.emu.get_symbol("___CFprogname")
            cf_process_path = self.emu.get_symbol("___CFProcessPath")

            self.emu.write_pointer(cf_progname.address, progname_str)
            self.emu.write_pointer(cf_process_path.address, process_path_str)

        # Set path forwarding to executable and Info.plist
        self.forward_path(
            src_path=self.executable_path,
            dst_path=self.executable_file,
        )
        self.forward_path(
            src_path=f"{bundle_path}/Info.plist",
            dst_path=info_path,
        )

    def get_executable_file(self) -> str:
        return self.executable_file

    def _fix_method_signature_rom_table(self):
        """Relocate references in `MethodSignatureROMTable`."""
        table = self.emu.get_symbol("_MethodSignatureROMTable")

        table_size = 7892

        objc_module = self.emu.find_module("libobjc.A.dylib")
        objc_offset = objc_module.base - objc_module.macho_info.image_base

        for index in range(table_size):
            offset = table.address + index * 24 + 8

            address = self.emu.read_pointer(offset)
            self.emu.write_pointer(offset, objc_offset + address)

    def _create_fp(self, fd: int, mode: str, unbuffered: bool = False) -> int:
        """Wrap file descriptor to file object by calling `fdopen`.

        Args:
            fd: File descriptor.
            mode: File open mode.
            unbuffered: If True, set unbuffered flag to the file object.

        Returns:
            File object pointer.
        """
        with self.emu.mem_context() as ctx:
            mode_ptr = ctx.create_string(mode)

            fp = self.emu.call_symbol("_fdopen", fd, mode_ptr)
            flags = self.emu.read_u32(fp + 16)

            if unbuffered:
                flags |= 0x2

            self.emu.write_u32(fp + 16, flags)
            return fp

    def _setup_standard_io(self):
        """Convert standard I/O file descriptors to FILE objects and assign them
        to target symbols.
        """
        stdin = self.emu.get_symbol("___stdinp")
        stdout = self.emu.get_symbol("___stdoutp")
        stderr = self.emu.get_symbol("___stderrp")

        if isinstance(self._stdin_fd, int):
            stdin_fp = self._create_fp(self._stdin_fd, "r")
            self.emu.write_pointer(stdin.address, stdin_fp)

        stdout_fp = self._create_fp(self._stdout_fd, "w", unbuffered=True)
        self.emu.write_pointer(stdout.address, stdout_fp)

        stderr_fp = self._create_fp(self._stderr_fd, "w", unbuffered=True)
        self.emu.write_pointer(stderr.address, stderr_fp)

    def dlopen(self, path: str) -> Optional[int]:
        """Used for `dlopen` and `_sl_dlopen_audited`.

        Presently supports system module loading only.

        Args:
            path: Module path or just the module name.

        Returns:
            If the module exists or is loaded successfully, returns the module's base
            address; otherwise returns `None`.
        """
        module_name = path.split("/")[-1]

        # Check module loading status
        for module in self.emu.modules:
            if path.endswith(module.name):
                return module.base

        # For system modules, attempt to load
        try:
            self.search_module_binary(module_name)
            self.resolve_modules([module_name])

            found_module = self.emu.find_module(module_name)
            if found_module:
                return found_module.base
        except FileNotFoundError:
            pass

        return None

    def set_dispatch_queue(self, queue: int):
        """Store current async dispatch queue in TLS.

        Certain async callback functions invoke `dispatch_assert_queue$V2`
        or `dispatch_assert_queue_not$V2` to perform assertion checks on
        the current dispatch queue.
        """
        self.emu.write_u64(TLS_ADDRESS + 0xA0, queue)
        self.emu.write_u64(TLS_ADDRESS + 0xA8, 0)

    def semaphore_create(self, value: int) -> int:
        sem = 1
        while sem < 10000:
            if sem not in self._semaphore_map:
                break
            sem += 1
        else:
            return 0

        self._semaphore_map[sem] = value
        return sem

    def semaphore_wait(self, semaphore: int, timeout: int = -1) -> int:
        start_time = time.time()
        value = self._semaphore_map[semaphore]

        # Blocked
        if value <= 0:
            rand_id = uuid.uuid4()

            if semaphore not in self._semaphore_queue:
                self._semaphore_queue[semaphore] = []
            self._semaphore_queue[semaphore].append(rand_id)

            while True:
                if 0 < timeout < time.time() - start_time:
                    return -1

                if rand_id not in self._semaphore_queue[semaphore]:
                    return 0

                time.sleep(0.1)

        self._semaphore_map[semaphore] -= 1
        return 0

    def semaphore_signal(self, semaphore: int):
        if self._semaphore_queue.get(semaphore):
            self._semaphore_queue[semaphore].pop(0)
        else:
            self._semaphore_map[semaphore] += 1

    @log_call
    def mach_port_construct(self) -> int:
        mach_port = self._mach_port_manager.new()
        return mach_port if mach_port else 0

    @log_call
    def mach_port_destruct(self, mach_port: int):
        self._mach_port_manager.free(mach_port)

    def bootstrap_look_up(self, name: str) -> int:
        """Find registered mach service.

        Returns:
            The port of this mach service.
        """
        if name in self._mach_services:
            return self._mach_services[name]

        return 0

    def mach_msg(
        self,
        msg: int,
        option: int,
        send_size: int,
        rcv_size: int,
        rcv_name: int,
        timeout: int,
        notify: int,
    ) -> int:
        """Respond to `mach_msg`."""
        return self._mach_msg_handler.handle_msg(
            msg,
            option,
            send_size,
            rcv_size,
            rcv_name,
            timeout,
            notify,
        )

    def xpc_connection_send_message(self, connection: int, message: int) -> int:
        """Respond to `xpc_connection_send_message_with_reply_sync`."""
        return self._xpc_message_handler.handle_message(
            connection,
            message,
        )

    def initialize(self):
        # Setup hooks
        self.emu.hooks.update(get_hooks())

        # Setup syscall handles
        self.emu.syscall_handlers.update(get_syscall_handlers())
        self.emu.syscall_names.update(get_syscall_names())

        self._setup_tls()

        # Mount virtual device files
        self.mount_devices(DEVICES_FILES)

        self._setup_system_registers()

        # Setup symbolic links
        for src, dst in SYMBOLIC_LINKS.items():
            self.set_symbolic_link(src, dst)

        self._setup_bundle_dir()

        # Setup mach services
        self._mach_services.update(self.MACH_SERVICES)

        # Setup system modules
        self.resolve_modules(SYSTEM_MODULES)
        self._init_system_symbols()

        self._setup_standard_io()
