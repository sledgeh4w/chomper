import datetime
import random
import time
import uuid
from functools import wraps
from typing import Callable, Dict

from chomper.exceptions import SymbolMissingException
from chomper.objc import ObjC
from chomper.utils import pyobj2cfobj

hooks: Dict[str, Callable] = {}


def get_hooks() -> Dict[str, Callable]:
    """Returns a dictionary of default hooks."""
    return hooks.copy()


def register_hook(symbol_name: str):
    """Decorator to register a hook function for a given symbol name."""

    def wrapper(func):
        @wraps(func)
        def decorator(uc, address, size, user_data):
            return func(uc, address, size, user_data)

        hooks[symbol_name] = decorator
        return func

    return wrapper


@register_hook("_os_unfair_lock_assert_owner")
def hook_os_unfair_lock_assert_owner(uc, address, size, user_data):
    pass


@register_hook("_stat")
def hook_stat(uc, address, size, user_data):
    emu = user_data["emu"]

    stat = emu.get_arg(1)

    # st_mode
    emu.write_u32(stat + 4, 0x4000)

    return 0


@register_hook("_lstat")
def hook_lstat(uc, address, size, user_data):
    emu = user_data["emu"]

    stat = emu.get_arg(1)

    # st_mode
    emu.write_u32(stat + 4, 0x4000)

    return 0


@register_hook("___sysctlbyname")
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
        variant_status = 0

        # can_has_debugger = 3
        variant_status |= 3 << 2

        # internal_release_type = 3
        variant_status |= 3 << 4

        emu.write_u64(oldp, variant_status)

    elif name == "hw.memsize":
        emu.write_u64(oldp, 4 * 1024 * 1024 * 1024)

    else:
        raise RuntimeError("Unhandled sysctl command: %s" % name)

    return 0


@register_hook("_getcwd")
def hook_getcwd(uc, address, size, user_data):
    emu = user_data["emu"]

    path = f"/private/var/containers/Bundle/Application/{uuid.uuid4()}/"

    buf = emu.get_arg(0)
    emu.write_string(buf, path)

    return 0


@register_hook("_opendir")
def hook_opendir(uc, address, size, user_data):
    return 0


@register_hook("_time")
def hook_time(uc, address, size, user_data):
    return int(time.time())


@register_hook("_srandom")
def hook_srandom(uc, address, size, user_data):
    return 0


@register_hook("_random")
def hook_random(uc, address, size, user_data):
    return random.randint(0, 2**32 - 1)


@register_hook("_localtime_r")
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


@register_hook("___srefill")
def hook_srefill(uc, address, size, user_data):
    return 0


@register_hook("_pthread_self")
def hook_pthread_self(uc, address, size, user_data):
    return 1


@register_hook("_pthread_rwlock_rdlock")
def hook_pthread_rwlock_rdlock(uc, address, size, user_data):
    return 0


@register_hook("_pthread_rwlock_unlock")
def hook_pthread_rwlock_unlock(uc, address, size, user_data):
    return 0


@register_hook("_getpwuid")
def hook_getpwuid(uc, address, size, user_data):
    return 0


@register_hook("_getpwuid_r")
def hook_getpwuid_r(uc, address, size, user_data):
    return 0


@register_hook("_malloc")
def hook_malloc(uc, address, size, user_data):
    emu = user_data["emu"]

    size = emu.get_arg(0)
    mem = emu.memory_manager.alloc(size)

    return mem


@register_hook("_calloc")
def hook_calloc(uc, address, size, user_data):
    emu = user_data["emu"]

    numitems = emu.get_arg(0)
    size = emu.get_arg(1)

    mem = emu.memory_manager.alloc(numitems * size)
    emu.write_bytes(mem, b"\x00" * (numitems * size))

    return mem


@register_hook("_realloc")
def hook_realloc(uc, address, size, user_data):
    emu = user_data["emu"]

    ptr = emu.get_arg(0)
    size = emu.get_arg(1)

    return emu.memory_manager.realloc(ptr, size)


@register_hook("_free")
def hook_free(uc, address, size, user_data):
    emu = user_data["emu"]

    mem = emu.get_arg(0)
    emu.memory_manager.free(mem)


@register_hook("_malloc_size")
def hook_malloc_size(uc, address, size, user_data):
    emu = user_data["emu"]

    mem = emu.get_arg(0)

    for pool in emu.memory_manager.pools:
        if pool.address <= mem < pool.address + pool.size:
            return pool.block_size

    return 0


@register_hook("_malloc_default_zone")
def hook_malloc_default_zone(uc, address, size, user_data):
    return 0


@register_hook("_malloc_zone_malloc")
def hook_malloc_zone_malloc(uc, address, size, user_data):
    emu = user_data["emu"]

    size = emu.get_arg(1)
    mem = emu.memory_manager.alloc(size)

    return mem


@register_hook("_malloc_zone_calloc")
def hook_malloc_zone_calloc(uc, address, size, user_data):
    emu = user_data["emu"]

    numitems = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(numitems * size)
    emu.write_bytes(mem, b"\x00" * (numitems * size))

    return mem


@register_hook("_malloc_zone_realloc")
def hook_malloc_zone_realloc(uc, address, size, user_data):
    emu = user_data["emu"]

    ptr = emu.get_arg(1)
    size = emu.get_arg(2)

    return emu.memory_manager.realloc(ptr, size)


@register_hook("_malloc_zone_free")
def hook_malloc_zone_free(uc, address, size, user_data):
    emu = user_data["emu"]

    mem = emu.get_arg(1)
    emu.memory_manager.free(mem)


@register_hook("_malloc_zone_from_ptr")
def hook_malloc_zone_from_ptr(uc, address, size, user_data):
    return 0


@register_hook("_malloc_zone_memalign")
def hook_malloc_zone_memalign(uc, address, size, user_data):
    emu = user_data["emu"]

    size = emu.get_arg(2)
    mem = emu.memory_manager.alloc(size)

    return mem


@register_hook("_malloc_good_size")
def hook_malloc_good_size(uc, address, size, user_data):
    emu = user_data["emu"]

    size = emu.get_arg(0)

    return size


@register_hook("_malloc_engaged_nano")
def hook_malloc_engaged_nano(uc, address, size, user_data):
    return 1


@register_hook("_posix_memalign")
def hook_posix_memalign(uc, address, size, user_data):
    emu = user_data["emu"]

    memptr = emu.get_arg(0)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(size)
    emu.write_pointer(memptr, mem)

    return 0


@register_hook("__os_activity_initiate")
def hook_os_activity_initiate(uc, address, size, user_data):
    return 0


@register_hook("_notify_register_dispatch")
def hook_notify_register_dispatch(uc, address, size, user_data):
    return 0


@register_hook("_dlsym")
def hook_dlsym(uc, address, size, user_data):
    emu = user_data["emu"]

    symbol_name = f"_{emu.read_string(emu.get_arg(1))}"

    try:
        symbol = emu.find_symbol(symbol_name)
        return symbol.address
    except SymbolMissingException:
        pass

    return 0


@register_hook("_dyld_program_sdk_at_least")
def hook_dyld_program_sdk_at_least(uc, address, size, user_data):
    return 0


@register_hook("_dispatch_async")
def hook_dispatch_async(uc, address, size, user_data):
    return 0


@register_hook("_uloc_getLanguage")
def hook_uloc_get_language(uc, address, size, user_data):
    return 0


@register_hook("_uloc_getScript")
def hook_uloc_get_script(uc, address, size, user_data):
    return 0


@register_hook("_uloc_getCountry")
def hook_uloc_get_country(uc, address, size, user_data):
    return 0


@register_hook("_uloc_getVariant")
def hook_uloc_get_variant(uc, address, size, user_data):
    return 0


@register_hook("_uloc_openKeywords")
def hook_uloc_open_keywords(uc, address, size, user_data):
    return 0


@register_hook("_uloc_getDisplayName")
def hook_uloc_get_display_name(uc, address, size, user_data):
    return 0


@register_hook("_uloc_getDisplayLanguage")
def hook_uloc_get_display_language(uc, address, size, user_data):
    return 0


@register_hook("_uenum_next")
def hook_uenum_next(uc, address, size, user_data):
    return 0


@register_hook("_uenum_close")
def hook_uenum_close(uc, address, size, user_data):
    return 0


@register_hook("_os_log_type_enabled")
def hook_os_log_type_enabled(uc, address, size, user_data):
    return 0


@register_hook("_MGCopyAnswer")
def hook_mg_copy_answer(uc, address, size, user_data):
    emu = user_data["emu"]
    objc = ObjC(emu)

    str_ptr = objc.msg_send(emu.get_arg(0), "cStringUsingEncoding:", 4)
    key = emu.read_string(str_ptr)

    if key in emu.os.device_info:
        return pyobj2cfobj(emu, emu.os.device_info[key])

    return 0


@register_hook("__CFPreferencesCopyAppValueWithContainerAndConfiguration")
def hook_cf_preferences_copy_app_value_with_container_and_configuration(
    uc, address, size, user_data
):
    emu = user_data["emu"]
    objc = ObjC(emu)

    str_ptr = objc.msg_send(emu.get_arg(0), "cStringUsingEncoding:", 4)
    key = emu.read_string(str_ptr)

    if key in emu.os.preferences:
        return pyobj2cfobj(emu, emu.os.preferences[key])

    return 0


@register_hook("__CFBundleCreateInfoDictFromMainExecutable")
def hook_cf_bundle_create_info_dict_from_main_executable(uc, address, size, user_data):
    return 0


@register_hook("___CFXPreferencesCopyCurrentApplicationStateWithDeadlockAvoidance")
def hook_cf_x_preferences_copy_current_application_state_with_deadlock_avoidance(
    uc, address, size, user_data
):
    emu = user_data["emu"]

    return pyobj2cfobj(emu, emu.os.preferences)


@register_hook("_CFNotificationCenterGetLocalCenter")
def hook_cf_notification_center_get_local_center(uc, address, size, user_data):
    return 0


@register_hook("__CFPrefsClientLog")
def hook_cf_prefs_client_log(uc, address, size, user_data):
    return 0


@register_hook("_NSLog")
def hook_ns_log(uc, address, size, user_data):
    return 0


@register_hook("_SecItemAdd")
def hook_sec_item_add(uc, address, size, user_data):
    return 0


@register_hook("_SecItemUpdate")
def hook_sec_item_update(uc, address, size, user_data):
    return 0


@register_hook("_SecItemDelete")
def hook_sec_item_delete(uc, address, size, user_data):
    return 0


@register_hook("_SecItemCopyMatching")
def hook_sec_item_copy_matching(uc, address, size, user_data):
    emu = user_data["emu"]
    objc = ObjC(emu)

    a1 = emu.get_arg(0)
    a2 = emu.get_arg(1)

    sec_return_data = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.find_symbol("_kSecReturnData").address),
    )

    sec_return_attributes = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.find_symbol("_kSecReturnAttributes").address),
    )

    sec_match_limit = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.find_symbol("_kSecMatchLimit").address),
    )

    cf_boolean_true = emu.read_pointer(emu.find_symbol("_kCFBooleanTrue").address)

    sec_match_limit_all = emu.read_pointer(
        emu.find_symbol("_kSecMatchLimitAll").address
    )

    if sec_match_limit == sec_match_limit_all:
        result = pyobj2cfobj(emu, [])
    elif sec_return_attributes == cf_boolean_true:
        result = pyobj2cfobj(emu, {})
    elif sec_return_data == cf_boolean_true:
        result = pyobj2cfobj(emu, b"")
    else:
        result = 0

    if a2:
        emu.write_u64(a2, result)

    return 0


@register_hook("_mach_vm_allocate")
def hook_mach_vm_allocate(uc, address, size, user_data):
    emu = user_data["emu"]

    addr = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(size)
    emu.write_pointer(addr, mem)

    return 0


@register_hook("_mach_vm_deallocate")
def hook_mach_vm_deallocate(uc, address, size, user_data):
    emu = user_data["emu"]

    mem = emu.get_arg(1)
    emu.memory_manager.free(mem)

    return 0
