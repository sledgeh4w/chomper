import os
import re
from functools import wraps
from typing import Callable, Dict, Optional

from unicorn import Uc

from chomper.exceptions import EmulatorCrashed, ObjCUnrecognizedSelector
from chomper.objc import ObjcRuntime, ObjcObject
from chomper.typing import HookContext
from chomper.utils import struct_to_bytes

from .structs import DlInfo


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

    return emu.read_pointer(emu.get_symbol("__main_thread_ptr").address)


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

    module_base = emu.ios_os.dlopen(path)
    if module_base is None:
        raise EmulatorCrashed(f"doesn't support dlopen: '{path}'")

    return module_base


@register_hook("_dladdr")
def hook_dladdr(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    addr = emu.get_arg(0)
    info = emu.get_arg(1)

    for module in emu.modules:
        if module.contains(addr):
            dl_info = DlInfo(
                dli_fname=emu.create_const_string(module.name),
                dli_fbase=module.base,
            )

            for symbol in module.symbols:
                if symbol.address == addr:
                    dl_info.dli_sname = emu.create_const_string(symbol.name)
                    dl_info.dli_saddr = symbol.address

            emu.write_bytes(info, struct_to_bytes(dl_info))
            return 1

    return 0


@register_hook("__sl_dlopen_audited")
def hook_sl_dlopen_audited(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    if not emu.get_arg(0):
        return emu.modules[-1].base

    path = emu.read_string(emu.read_pointer(emu.get_arg(0)))

    module_base = emu.ios_os.dlopen(path)
    if module_base is None:
        raise EmulatorCrashed(f"doesn't support _sl_dlopen_audited: '{path}'")

    return module_base


@register_hook("_dlsym")
def hook_dlsym(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    name = f"_{emu.read_string(emu.get_arg(1))}"

    symbol = emu.find_symbol(name)
    if not symbol:
        return 0

    return symbol.address


@register_hook("_dyld_program_sdk_at_least")
def hook_dyld_program_sdk_at_least(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    return 0


@register_hook("_dyld_image_header_containing_address")
def hook_dyld_image_header_containing_address(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    address = emu.get_arg(0)

    for module in emu.modules:
        if module.contains(address):
            return module.dyld_info.image_header

    return 0


@register_hook("__dyld_shared_cache_real_path")
def hook_dyld_shared_cache_real_path(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    path = emu.get_arg(0)

    return path


@register_hook("__dyld_get_image_header")
def hook_dyld_get_image_header(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    if emu.modules:
        module = emu.modules[-1]
        return module.dyld_info.image_header

    return 0


@register_hook("__dyld_get_image_vmaddr_slide")
def hook_dyld_get_image_vmaddr_slide(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    if emu.modules:
        module = emu.modules[-1]
        return module.base - module.dyld_info.image_base

    return 0


@register_hook("__NSGetExecutablePath")
def hook_ns_get_executable_path(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    buf = emu.get_arg(0)
    buf_size = emu.get_arg(1)

    path = emu.ios_os.executable_path
    emu.write_u32(buf_size, len(path))

    if buf:
        emu.write_string(buf, path)

    return 0


@register_hook("_dispatch_async")
def hook_dispatch_async(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    queue = emu.get_arg(0)
    block = emu.get_arg(1)

    invoke = emu.read_pointer(block + 16)

    do_invoke = False

    libcupolicy = emu.find_module("libcupolicy.dylib")
    if libcupolicy:
        for symbol in libcupolicy.symbols:
            if (
                re.match(r".*ctu.*SharedSynchronizable.*", symbol.name)
                and invoke == symbol.address
            ):
                do_invoke = True

    if do_invoke:
        emu.logger.info("Invoke block: %s", emu.debug_symbol(invoke))

        emu.ios_os.set_dispatch_queue(queue)
        emu.call_address(invoke, block)

        return 0

    from_addr = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
    emu.logger.warning(f"Ignored a 'dispatch_async' call from {from_addr}.")

    return 0


@register_hook("_dispatch_barrier_async")
def hook_dispatch_barrier_async(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    from_addr = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
    emu.logger.warning(f"Ignored a 'dispatch_barrier_async' call from {from_addr}.")

    return 0


@register_hook("__xpc_look_up_endpoint")
def hook_xpc_look_up_endpoint(uc: Uc, address: int, size: int, user_data: HookContext):
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

    executable_dir = os.path.dirname(emu.ios_os.get_executable_file())
    info_path = os.path.join(executable_dir, "Info.plist")

    if not os.path.exists(info_path):
        # Ensure `_mainBundleLock` is released
        main_bundle_lock = emu.get_symbol("__mainBundleLock")
        emu.call_symbol("_pthread_mutex_unlock", main_bundle_lock.address)

        raise FileNotFoundError(
            "File 'Info.plist' not found, please ensure that 'Info.plist' "
            "and executable file are in the same directory."
        )

    with open(info_path, "rb") as f:
        info_content = f.read()

    with emu.mem_context() as ctx:
        info_data = ctx.create_buffer(len(info_content) + 100)
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
        emu.read_pointer(emu.get_symbol("_kSecReturnData").address),
    )
    assert isinstance(sec_return_data, ObjcObject)

    sec_return_attributes = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.get_symbol("_kSecReturnAttributes").address),
    )
    assert isinstance(sec_return_attributes, ObjcObject)

    sec_match_limit = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.get_symbol("_kSecMatchLimit").address),
    )
    assert isinstance(sec_match_limit, ObjcObject)

    cf_boolean_true = emu.read_pointer(emu.get_symbol("_kCFBooleanTrue").address)

    sec_match_limit_all = emu.read_pointer(emu.get_symbol("_kSecMatchLimitAll").address)

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

    service_name = emu.read_string(emu.get_arg(1))
    service_port = emu.get_arg(2)

    emu.logger.info(
        "'bootstrap_look_up3' is called to look up '%s' service", service_name
    )

    port = emu.ios_os.bootstrap_look_up(service_name)

    if port:
        emu.write_u32(service_port, port)

    return 0


@register_hook("_xpc_connection_send_message_with_reply_sync")
def hook_xpc_connection_send_message_with_reply_sync(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    connection = emu.get_arg(0)
    message = emu.get_arg(1)

    return emu.ios_os.xpc_send_message(connection, message)


@register_hook("+[NSObject(NSObject) doesNotRecognizeSelector:]")
def hook_ns_object_does_not_recognize_selector_for_class(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    receiver = emu.get_arg(0)
    selector = emu.read_string(emu.get_arg(2))

    class_name = emu.read_string(emu.call_symbol("_class_getName", receiver))

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
