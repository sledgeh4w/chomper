import os
from functools import wraps
from typing import Callable, Dict

from chomper.exceptions import SymbolMissing, ObjCUnrecognizedSelector
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


@register_hook("_opendir")
def hook_opendir(uc, address, size, user_data):
    emu = user_data["emu"]

    path = emu.read_string(emu.get_arg(0))

    return emu.file_manager.opendir(path)


@register_hook("_readdir")
def hook_readdir(uc, address, size, user_data):
    emu = user_data["emu"]

    dirp = emu.get_arg(0)

    return emu.file_manager.readdir(dirp)


@register_hook("_closedir")
def hook_closedir(uc, address, size, user_data):
    emu = user_data["emu"]

    dirp = emu.get_arg(0)

    return emu.file_manager.closedir(dirp)


@register_hook("___srefill")
def hook_srefill(uc, address, size, user_data):
    return 1


@register_hook("_pthread_self")
def hook_pthread_self(uc, address, size, user_data):
    return 1


@register_hook("_pthread_rwlock_rdlock")
@register_hook("_pthread_rwlock_rdlock$VARIANT$armv81")
def hook_pthread_rwlock_rdlock(uc, address, size, user_data):
    return 0


@register_hook("_pthread_rwlock_wrlock")
@register_hook("_pthread_rwlock_wrlock$VARIANT$armv81")
def hook_pthread_rwlock_wrlock(uc, address, size, user_data):
    return 0


@register_hook("_pthread_rwlock_unlock")
@register_hook("_pthread_rwlock_unlock$VARIANT$armv81")
def hook_pthread_rwlock_unlock(uc, address, size, user_data):
    return 0


@register_hook("_pthread_mutex_lock")
def hook_pthread_mutex_lock(uc, address, size, user_data):
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
    except SymbolMissing:
        pass

    return 0


@register_hook("_dyld_program_sdk_at_least")
def hook_dyld_program_sdk_at_least(uc, address, size, user_data):
    return 0


@register_hook("_dispatch_async")
def hook_dispatch_async(uc, address, size, user_data):
    return 0


@register_hook("_dispatch_resume")
def hook_dispatch_resume(uc, address, size, user_data):
    return 0


@register_hook("_os_log_type_enabled")
def hook_os_log_type_enabled(uc, address, size, user_data):
    return 0


@register_hook("_os_log_create")
def hook_os_log_create(uc, address, size, user_data):
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
    emu = user_data["emu"]

    executable_dir = os.path.dirname(emu.os.executable_path)
    info_path = os.path.join(executable_dir, "Info.plist")

    if not os.path.exists(info_path):
        raise FileNotFoundError(
            "File 'Info.plist' not found, please ensure that 'Info.plist' "
            "and executable file are in the same directory."
        )

    with open(info_path, "rb") as f:
        info_content = f.read()

    info_data = emu.create_buffer(len(info_content) + 100)
    emu.write_bytes(info_data, info_content)

    cf_bundle = emu.call_symbol(
        "__CFBundleCreateInfoDictFromData", info_data, len(info_content)
    )

    return cf_bundle


@register_hook("__CFBundleResourceLogger")
def hook_cf_bundle_resource_logger(uc, address, size, user_data):
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


@register_hook("_CFNotificationCenterAddObserver")
def hook_cf_notification_center_add_observer(uc, address, size, user_data):
    return 0


@register_hook("_CFNotificationCenterPostNotification")
def hook_cf_notification_center_post_notification(uc, address, size, user_data):
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


@register_hook("+[NSObject(NSObject) doesNotRecognizeSelector:]")
def hook_ns_object_does_not_recognize_selector_for_class(uc, address, size, user_data):
    emu = user_data["emu"]

    receiver = emu.get_arg(0)
    selector = emu.read_string(emu.get_arg(2))

    class_name = emu.read_string(emu.call_symbol("_class_getName", receiver))
    raise ObjCUnrecognizedSelector(
        f"Unrecognized selector '{selector}' of class '{class_name}'"
    )


@register_hook("-[NSObject(NSObject) doesNotRecognizeSelector:]")
def hook_ns_object_does_not_recognize_selector_for_instance(
    uc, address, size, user_data
):
    emu = user_data["emu"]

    receiver = emu.get_arg(0)
    selector = emu.read_string(emu.get_arg(2))

    class_ = emu.call_symbol("_object_getClass", receiver)
    class_name = emu.read_string(emu.call_symbol("_class_getName", class_))
    raise ObjCUnrecognizedSelector(
        f"Unrecognized selector '{selector}' of instance '{class_name}'"
    )
