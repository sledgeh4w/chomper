import os
from functools import wraps
from typing import Callable, Dict, Optional

from unicorn import Uc, UcError

from chomper.exceptions import EmulatorCrashed, SymbolMissing, ObjCUnrecognizedSelector
from chomper.objc import ObjcRuntime, ObjcObject
from chomper.typing import HookContext

hooks: Dict[str, Callable] = {}


def get_hooks() -> Dict[str, Callable]:
    """Returns a dictionary of default hooks."""
    return hooks.copy()


def register_hook(symbol_name: str):
    """Decorator to register a hook function for a given symbol name."""

    def wrapper(f):
        @wraps(f)
        def decorator(
            uc: Uc, address: int, size: int, user_data: HookContext
        ) -> Optional[int]:
            return f(uc, address, size, user_data)

        hooks[symbol_name] = decorator
        return f

    return wrapper


@register_hook("_pthread_self")
def hook_pthread_self(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    return emu.read_pointer(emu.find_symbol("__main_thread_ptr").address)


@register_hook("_malloc")
def hook_malloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    size = emu.get_arg(0)
    mem = emu.memory_manager.alloc(size)

    return mem


@register_hook("_calloc")
def hook_calloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    numitems = emu.get_arg(0)
    size = emu.get_arg(1)

    mem = emu.memory_manager.alloc(numitems * size)
    emu.write_bytes(mem, b"\x00" * (numitems * size))

    return mem


@register_hook("_realloc")
def hook_realloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    ptr = emu.get_arg(0)
    size = emu.get_arg(1)

    return emu.memory_manager.realloc(ptr, size)


@register_hook("_free")
def hook_free(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    mem = emu.get_arg(0)
    emu.memory_manager.free(mem)


@register_hook("_malloc_size")
def hook_malloc_size(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    mem = emu.get_arg(0)

    for pool in emu.memory_manager.pools:
        if pool.address <= mem < pool.address + pool.size:
            return pool.block_size

    return 0


@register_hook("_malloc_default_zone")
def hook_malloc_default_zone(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_malloc_create_zone")
def hook_malloc_create_zone(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_malloc_set_zone_name")
def hook_malloc_set_zone_name(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_malloc_zone_malloc")
def hook_malloc_zone_malloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    size = emu.get_arg(1)
    mem = emu.memory_manager.alloc(size)

    return mem


@register_hook("_malloc_zone_calloc")
def hook_malloc_zone_calloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    numitems = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(numitems * size)
    emu.write_bytes(mem, b"\x00" * (numitems * size))

    return mem


@register_hook("_malloc_zone_realloc")
def hook_malloc_zone_realloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    ptr = emu.get_arg(1)
    size = emu.get_arg(2)

    return emu.memory_manager.realloc(ptr, size)


@register_hook("_malloc_zone_free")
def hook_malloc_zone_free(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    mem = emu.get_arg(1)
    emu.memory_manager.free(mem)


@register_hook("_malloc_zone_from_ptr")
def hook_malloc_zone_from_ptr(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_malloc_zone_memalign")
def hook_malloc_zone_memalign(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    alignment = emu.get_arg(1)
    size = emu.get_arg(2)
    mem = emu.memory_manager.memalign(alignment, size)

    return mem


@register_hook("_malloc_good_size")
def hook_malloc_good_size(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    size = emu.get_arg(0)

    return size


@register_hook("_malloc_engaged_nano")
def hook_malloc_engaged_nano(uc: Uc, address: int, size: int, user_data: HookContext):
    return 1


@register_hook("_posix_memalign")
def hook_posix_memalign(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    memptr = emu.get_arg(0)
    alignment = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.memalign(alignment, size)
    emu.write_pointer(memptr, mem)

    return 0


@register_hook("_dlopen")
def hook_dlopen(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    if not emu.get_arg(0):
        return emu.modules[-1].base

    path = emu.read_string(emu.get_arg(0))

    module_base = emu.ios_os.load_module_private(path)
    if module_base is None:
        raise EmulatorCrashed(f"doesn't support dlopen: '{path}'")

    return module_base


@register_hook("__sl_dlopen_audited")
def hook_sl_dlopen_audited(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    if not emu.get_arg(0):
        return emu.modules[-1].base

    path = emu.read_string(emu.read_pointer(emu.get_arg(0)))

    module_base = emu.ios_os.load_module_private(path)
    if module_base is None:
        raise EmulatorCrashed(f"doesn't support _sl_dlopen_audited: '{path}'")

    return module_base


@register_hook("_dlsym")
def hook_dlsym(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    symbol_name = f"_{emu.read_string(emu.get_arg(1))}"

    try:
        symbol = emu.find_symbol(symbol_name)
        return symbol.address
    except SymbolMissing:
        pass

    return 0


@register_hook("_dyld_program_sdk_at_least")
def hook_dyld_program_sdk_at_least(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    return 0


@register_hook("_dispatch_async")
def hook_dispatch_async(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    from_ = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
    emu.logger.warning(f"Emulator ignored a 'dispatch_async' call from {from_}.")

    return 0


@register_hook("_dispatch_barrier_async")
def hook_dispatch_barrier_async(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    from_ = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
    emu.logger.warning(
        f"Emulator ignored a 'dispatch_barrier_async' call from {from_}."
    )

    return 0


@register_hook("_MGCopyAnswer")
def hook_mg_copy_answer(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]
    objc = ObjcRuntime(emu)

    str_ptr = objc.msg_send(emu.get_arg(0), "UTF8String")
    assert isinstance(str_ptr, int)

    key = emu.read_string(str_ptr)

    if key in emu.ios_os.device_info:
        return objc.create_cf_string(emu.ios_os.device_info[key])

    return 0


@register_hook("__CFPreferencesCopyAppValueWithContainerAndConfiguration")
def hook_cf_preferences_copy_app_value_with_container_and_configuration(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]
    objc = ObjcRuntime(emu)

    str_ptr = objc.msg_send(emu.get_arg(0), "UTF8String")
    assert isinstance(str_ptr, int)

    key = emu.read_string(str_ptr)

    if key in emu.ios_os.preferences:
        return objc.create_cf_string(emu.ios_os.preferences[key])

    return 0


@register_hook("__CFBundleCreateInfoDictFromMainExecutable")
def hook_cf_bundle_create_info_dict_from_main_executable(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    executable_dir = os.path.dirname(emu.ios_os.executable_path)
    info_path = os.path.join(executable_dir, "Info.plist")

    if not os.path.exists(info_path):
        # Ensure `_mainBundleLock` is released
        main_bundle_lock = emu.find_symbol("__mainBundleLock")
        emu.call_symbol("_pthread_mutex_unlock", main_bundle_lock.address)

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


@register_hook("___CFXPreferencesCopyCurrentApplicationStateWithDeadlockAvoidance")
def hook_cf_x_preferences_copy_current_application_state_with_deadlock_avoidance(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]
    objc = ObjcRuntime(emu)

    return objc.create_cf_dictionary(emu.ios_os.preferences)


@register_hook("_SecItemAdd")
def hook_sec_item_add(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_SecItemUpdate")
def hook_sec_item_update(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_SecItemDelete")
def hook_sec_item_delete(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_SecItemCopyMatching")
def hook_sec_item_copy_matching(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]
    objc = ObjcRuntime(emu)

    a1 = emu.get_arg(0)
    a2 = emu.get_arg(1)

    sec_return_data = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.find_symbol("_kSecReturnData").address),
    )
    assert isinstance(sec_return_data, ObjcObject)

    sec_return_attributes = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.find_symbol("_kSecReturnAttributes").address),
    )
    assert isinstance(sec_return_attributes, ObjcObject)

    sec_match_limit = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.find_symbol("_kSecMatchLimit").address),
    )
    assert isinstance(sec_match_limit, ObjcObject)

    cf_boolean_true = emu.read_pointer(emu.find_symbol("_kCFBooleanTrue").address)

    sec_match_limit_all = emu.read_pointer(
        emu.find_symbol("_kSecMatchLimitAll").address
    )

    if sec_match_limit.value == sec_match_limit_all:
        result = objc.create_cf_array([])
    elif sec_return_attributes.value == cf_boolean_true:
        result = objc.create_cf_dictionary({})
    elif sec_return_data.value == cf_boolean_true:
        # result = objc.create_cf_data(b"")
        result = 0
    else:
        result = 0

    if a2:
        emu.write_u64(a2, result)

    return 0


@register_hook("_bootstrap_look_up3")
def hook_bootstrap_look_up3(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    mach_service_map = {
        "com.apple.system.notification_center": (
            emu.ios_os.MACH_PORT_NOTIFICATION_CENTER
        ),
        "com.apple.CARenderServer": emu.ios_os.MACH_PORT_CA_RENDER_SERVER,
    }

    service_name = emu.read_string(emu.get_arg(1))
    service_port = emu.get_arg(2)

    emu.logger.info(
        "'bootstrap_look_up3' is called to look up '%s' service", service_name
    )

    if service_name in mach_service_map:
        emu.write_u32(service_port, mach_service_map[service_name])

    return 0


@register_hook("+[NSObject(NSObject) doesNotRecognizeSelector:]")
def hook_ns_object_does_not_recognize_selector_for_class(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    receiver = emu.get_arg(0)
    selector = emu.read_string(emu.get_arg(2))

    class_name = emu.read_string(emu.call_symbol("_class_getName", receiver))
    emu.log_backtrace()
    raise ObjCUnrecognizedSelector(
        f"Unrecognized selector '{selector}' of class '{class_name}'"
    )


@register_hook("-[NSObject(NSObject) doesNotRecognizeSelector:]")
def hook_ns_object_does_not_recognize_selector_for_instance(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    receiver = emu.get_arg(0)
    selector = emu.read_string(emu.get_arg(2))

    class_ = emu.call_symbol("_object_getClass", receiver)
    class_name = emu.read_string(emu.call_symbol("_class_getName", class_))
    raise ObjCUnrecognizedSelector(
        f"Unrecognized selector '{selector}' of instance '{class_name}'"
    )


@register_hook("__ZL9readClassP10objc_classbb")
def hook_read_class(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    a1 = emu.get_arg(0)
    a2 = emu.get_arg(1)
    a3 = emu.get_arg(2)

    context = emu.uc.context_save()

    class_name = ""

    try:
        data_ptr = emu.read_pointer(a1 + 32)
        if data_ptr:
            name_ptr = emu.read_pointer(data_ptr + 24)
            class_name = emu.read_string(name_ptr)
    except (UnicodeDecodeError, UcError):
        pass

    emu.uc.reg_write(emu.arch.reg_sp, emu.uc.reg_read(emu.arch.reg_sp) - 0x60)

    try:
        read_class_addr = emu.find_symbol("__ZL9readClassP10objc_classbb").address
        result = emu.call_address(read_class_addr + 4, a1, a2, a3)
    except EmulatorCrashed:
        emu.logger.warning(
            "readClass failed: %s",
            f'"{class_name}"' if class_name else emu.debug_symbol(a1),
        )
        result = 0
    finally:
        emu.uc.context_restore(context)

    return result
