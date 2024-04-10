import datetime
import random
import time
import uuid

from chomper.types import FuncHooks


class IosFuncHooks(FuncHooks):
    """System function hooks for the iOS."""

    @classmethod
    def register(cls, emu):
        retval_hooks = {
            # libsystem_pthread.dylib
            "_pthread_self": 1,
            "_pthread_rwlock_rdlock": 0,
            "_pthread_rwlock_unlock": 0,
            # libsystem_platform.dylib
            "_os_unfair_lock_assert_owner": None,
            # libsystem_info.dylib
            "_getpwuid": 0,
            "_getpwuid_r": 0,
            # libsystem_trace.dylib
            "__os_activity_initiate": 0,
            # libsystem_notify.dylib
            "_notify_register_dispatch": 0,
            # libdispatch.dylib
            "_dispatch_async": 0,
            # libdyld.dylib
            "_dyld_program_sdk_at_least": 1,
            # libobjc.A.dylib
            "__ZN11objc_object16rootAutorelease2Ev": None,
            # CoreFoundation
            "__CFBundleCreateInfoDictFromMainExecutable": 0,
            # Foundation
            "_NSLog": 0,
        }

        hooks = {
            # libsystem_malloc.dylib
            "_malloc": cls.hook_malloc,
            "_calloc": cls.hook_calloc,
            "_realloc": cls.hook_realloc,
            "_free": cls.hook_free,
            "_malloc_size": cls.hook_malloc_size,
            "_malloc_default_zone": cls.hook_malloc_default_zone,
            "_malloc_zone_malloc": cls.hook_malloc_zone_malloc,
            "_malloc_zone_calloc": cls.hook_malloc_zone_calloc,
            "_malloc_zone_realloc": cls.hook_malloc_zone_realloc,
            "_malloc_zone_free": cls.hook_malloc_zone_free,
            "_malloc_zone_from_ptr": cls.hook_malloc_zone_from_ptr,
            "_malloc_zone_memalign": cls.hook_malloc_zone_memalign,
            "_malloc_good_size": cls.hook_malloc_good_size,
            "_malloc_engaged_nano": cls.hook_malloc_engaged_nano,
            "_posix_memalign": cls.hook_posix_memalign,
            # libsystem_c.dylib
            "_getcwd": cls.hook_getcwd,
            "_opendir": cls.hook_opendir,
            "_time": cls.hook_time,
            "_srandom": cls.hook_srandom,
            "_random": cls.hook_random,
            "_localtime_r": cls.hook_localtime_r,
            "___srefill": cls.hook_srefill,
            # libsystem_kernel.dylib
            "_stat": cls.hook_stat,
            "_lstat": cls.hook_lstat,
            "___sysctlbyname": cls.hook_sysctlbyname,
            # libmacho.dylib
            "_getsectiondata": cls.hook_getsectiondata,
            "_getsegmentdata": cls.hook_getsegmentdata,
        }

        for func_name, retval in retval_hooks.items():
            hooks[func_name] = cls.hook_retval(retval)

        emu.hooks.update(hooks)

    @staticmethod
    def hook_malloc(uc, address, size, user_data):
        emu = user_data["emu"]

        size = emu.get_arg(0)
        mem = emu.memory_manager.alloc(size)

        return mem

    @staticmethod
    def hook_calloc(uc, address, size, user_data):
        emu = user_data["emu"]

        numitems = emu.get_arg(0)
        size = emu.get_arg(1)

        mem = emu.memory_manager.alloc(numitems * size)
        emu.write_bytes(mem, b"\x00" * (numitems * size))

        return mem

    @staticmethod
    def hook_realloc(uc, address, size, user_data):
        emu = user_data["emu"]

        ptr = emu.get_arg(0)
        size = emu.get_arg(1)

        return emu.memory_manager.realloc(ptr, size)

    @staticmethod
    def hook_free(uc, address, size, user_data):
        emu = user_data["emu"]

        mem = emu.get_arg(0)
        emu.memory_manager.free(mem)

    @staticmethod
    def hook_malloc_size(uc, address, size, user_data):
        emu = user_data["emu"]

        mem = emu.get_arg(0)

        for pool in emu.memory_manager.pools:
            if pool.address <= mem < pool.address + pool.size:
                return pool.block_size

        return 0

    @staticmethod
    def hook_malloc_default_zone(uc, address, size, user_data):
        return 0

    @staticmethod
    def hook_malloc_zone_malloc(uc, address, size, user_data):
        emu = user_data["emu"]

        size = emu.get_arg(1)
        mem = emu.memory_manager.alloc(size)

        return mem

    @staticmethod
    def hook_malloc_zone_calloc(uc, address, size, user_data):
        emu = user_data["emu"]

        numitems = emu.get_arg(1)
        size = emu.get_arg(2)

        mem = emu.memory_manager.alloc(numitems * size)
        emu.write_bytes(mem, b"\x00" * (numitems * size))

        return mem

    @staticmethod
    def hook_malloc_zone_realloc(uc, address, size, user_data):
        emu = user_data["emu"]

        ptr = emu.get_arg(1)
        size = emu.get_arg(2)

        return emu.memory_manager.realloc(ptr, size)

    @staticmethod
    def hook_malloc_zone_free(uc, address, size, user_data):
        emu = user_data["emu"]

        mem = emu.get_arg(1)
        emu.memory_manager.free(mem)

    @staticmethod
    def hook_malloc_zone_from_ptr(uc, address, size, user_data):
        return 0

    @staticmethod
    def hook_malloc_zone_memalign(uc, address, size, user_data):
        emu = user_data["emu"]

        size = emu.get_arg(2)
        mem = emu.memory_manager.alloc(size)

        return mem

    @staticmethod
    def hook_malloc_good_size(uc, address, size, user_data):
        emu = user_data["emu"]

        size = emu.get_arg(0)

        return size

    @staticmethod
    def hook_malloc_engaged_nano(uc, address, size, user_data):
        return 1

    @staticmethod
    def hook_posix_memalign(uc, address, size, user_data):
        emu = user_data["emu"]

        memptr = emu.get_arg(0)
        size = emu.get_arg(2)

        mem = emu.memory_manager.alloc(size)
        emu.write_pointer(memptr, mem)

        return 0

    @staticmethod
    def hook_os_unfair_lock_assert_owner(uc, address, size, user_data):
        pass

    @staticmethod
    def hook_srefill(uc, address, size, user_data):
        return 0

    @staticmethod
    def hook_getcwd(uc, address, size, user_data):
        emu = user_data["emu"]

        path = f"/private/var/containers/Bundle/Application/{uuid.uuid4()}/"

        buf = emu.get_arg(0)
        emu.write_string(buf, path)

        return 0

    @staticmethod
    def hook_opendir(uc, address, size, user_data):
        return 0

    @staticmethod
    def hook_time(uc, address, size, user_data):
        return int(time.time())

    @staticmethod
    def hook_srandom(uc, address, size, user_data):
        return 0

    @staticmethod
    def hook_random(uc, address, size, user_data):
        return random.randint(0, 2**32 - 1)

    @staticmethod
    def hook_localtime_r(uc, address, size, user_data):
        emu = user_data["emu"]

        tp = emu.read_u64(emu.get_arg(0))
        tm = emu.get_arg(1)

        date = datetime.datetime.fromtimestamp(tp)

        emu.write_u32(tm, date.second)
        emu.write_u32(tm + 4, date.minute)
        emu.write_u32(tm + 8, date.hour)
        emu.write_u32(tm + 12, date.day)
        emu.write_u32(tm + 16, date.month)
        emu.write_u32(tm + 20, date.year)
        emu.write_u32(tm + 24, 0)
        emu.write_u32(tm + 28, 0)
        emu.write_u32(tm + 32, 0)
        emu.write_u64(tm + 40, 8 * 60 * 60)

        return 0

    @staticmethod
    def hook_fopen(uc, address, size, user_data):
        emu = user_data["emu"]

        path = emu.read_string(emu.get_arg(0))
        emu.logger.info("fopen: %s" % path)

        return 0

    @staticmethod
    def hook_stat(uc, address, size, user_data):
        emu = user_data["emu"]

        stat = emu.get_arg(1)

        # st_mode
        emu.write_u32(stat + 4, 0x4000)

        return 0

    @staticmethod
    def hook_lstat(uc, address, size, user_data):
        emu = user_data["emu"]

        stat = emu.get_arg(1)

        # st_mode
        emu.write_u32(stat + 4, 0x4000)

        return 0

    @staticmethod
    def hook_sysctlbyname(uc, address, size, user_data):
        emu = user_data["emu"]

        name = emu.read_string(emu.get_arg(0))
        oldp = emu.get_arg(2)
        oldlenp = emu.get_arg(3)

        if not oldp or not oldlenp:
            return 0

        if name == "kern.boottime":
            emu.write_u64(oldp, int(time.time()) - 3600 * 24)
            emu.write_u64(oldp + 8, 0)

        elif name == "kern.osvariant_status":
            # internal_release_type = 3
            emu.write_u64(oldp, 0x30)

        elif name == "hw.memsize":
            emu.write_u64(oldp, 4 * 1024 * 1024 * 1024)

        else:
            emu.logger.info([emu.debug_symbol(t[0]) for t in emu.backtrace()])
            raise RuntimeError("Unhandled sysctl command: %s" % name)

        return 0

    @staticmethod
    def hook_getsectiondata(uc, address, size, user_data):
        emu = user_data["emu"]
        module = emu.modules[-1]

        section_name = emu.read_string(emu.get_arg(2))
        size_ptr = emu.get_arg(3)

        section = module.binary.get_section(section_name)
        if not section:
            return 0

        emu.write_u64(size_ptr, section.size)

        return module.base - module.image_base + section.virtual_address

    @staticmethod
    def hook_getsegmentdata(uc, address, size, user_data):
        emu = user_data["emu"]
        module = emu.modules[-1]

        segment_name = emu.read_string(emu.get_arg(1))
        size_ptr = emu.get_arg(2)

        segment = module.binary.get_segment(segment_name)
        if not segment:
            return 0

        emu.write_u64(size_ptr, segment.virtual_size)

        return module.base - module.image_base + segment.virtual_address
