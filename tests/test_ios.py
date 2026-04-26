import os
from ctypes import sizeof

from chomper.os.ios import const
from chomper.os.ios.structs import MachTimespec


def test_ns_number(emu_ios, objc):
    sample_int = 1

    with objc.autorelease_pool():
        ns_number_class = objc.find_class("NSNumber")
        assert ns_number_class

        number = objc.msg_send("NSNumber", "numberWithInteger:", sample_int)
        assert number

        raw_value = number.call_method("intValue")
        assert sample_int == raw_value


def test_ns_string(emu_ios, objc):
    with objc.autorelease_pool():
        ns_string_class = objc.find_class("NSString")
        assert ns_string_class

        string = ns_string_class.call_method("stringWithUTF8String:", "Mocha")
        assert string


def test_ns_mutable_string(emu_ios, objc):
    sample_str = "Mocha"

    with objc.autorelease_pool():
        ns_mutable_string_class = objc.find_class("NSMutableString")
        assert ns_mutable_string_class

        string = ns_mutable_string_class.call_method("string")

        string.call_method("setString:", objc.create_ns_string(sample_str))
        raw_string = string.call_method("UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str

        string.call_method("appendString:", objc.create_ns_string(sample_str))
        raw_string = string.call_method("UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str * 2


def test_ns_array(emu_ios, objc):
    sample_str = "Mocha"

    with objc.autorelease_pool():
        ns_array_class = objc.find_class("NSArray")
        assert ns_array_class

        array = ns_array_class.call_method(
            "arrayWithObjects:", objc.create_ns_string(sample_str)
        )
        assert array

        first_object = array.call_method("objectAtIndex:", 0)
        raw_string = objc.msg_send(first_object, "UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str

        description = array.call_method("description")
        assert description


def test_ns_mutable_array(emu_ios, objc):
    sample_str = "Mocha"

    with objc.autorelease_pool():
        ns_mutable_array_class = objc.find_class("NSMutableArray")
        assert ns_mutable_array_class

        array = ns_mutable_array_class.call_method("array")
        assert array

        array.call_method("addObject:", objc.create_ns_string(sample_str))

        first_object = array.call_method("objectAtIndex:", 0)
        raw_string = first_object.call_method("UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str


def test_ns_dictionary(emu_ios, objc):
    sample_key = "name"
    sample_value = "Mocha"

    with objc.autorelease_pool():
        ns_dictionary_class = objc.find_class("NSDictionary")
        assert ns_dictionary_class

        key = objc.create_ns_string(sample_key)
        value = objc.create_ns_string(sample_value)

        dictionary = ns_dictionary_class.call_method(
            "dictionaryWithObjectsAndKeys:",
            value,
            va_list=(key,),
        )
        assert dictionary

        value2 = dictionary.call_method("objectForKey:", key)
        raw_string = value2.call_method("UTF8String")
        assert emu_ios.read_string(raw_string) == sample_value

        description = dictionary.call_method("description")
        assert description


def test_ns_mutable_dictionary(emu_ios, objc):
    sample_key = "name"
    sample_value = "Mocha"

    with objc.autorelease_pool():
        ns_mutable_dictionary_class = objc.find_class("NSMutableDictionary")
        assert ns_mutable_dictionary_class

        dictionary = ns_mutable_dictionary_class.call_method("dictionary")
        assert dictionary

        key = objc.create_ns_string(sample_key)
        value = objc.create_ns_string(sample_value)

        dictionary.call_method("setObject:forKey:", value, key)

        value2 = dictionary.call_method("objectForKey:", key)
        raw_string = value2.call_method("UTF8String")
        assert emu_ios.read_string(raw_string) == sample_value


def test_ns_data(emu_ios, objc):
    sample_bytes = b"Mocha"

    with emu_ios.memory_scope() as mem, objc.autorelease_pool():
        ns_data_class = objc.find_class("NSData")
        assert ns_data_class

        buffer = mem.create_buffer(len(sample_bytes))
        emu_ios.write_bytes(buffer, sample_bytes)

        data = ns_data_class.call_method(
            "dataWithBytes:length:", buffer, len(sample_bytes)
        )
        assert data


def test_ns_data_with_large_size(emu_ios, objc):
    """When the size of `NSData` exceeds 64k, `vm_allocate` will be called."""
    sample_bytes = bytes(1024 * 64)

    with emu_ios.memory_scope() as mem, objc.autorelease_pool():
        ns_data_class = objc.find_class("NSData")
        assert ns_data_class

        buffer = mem.create_buffer(len(sample_bytes))
        emu_ios.write_bytes(buffer, sample_bytes)

        data = ns_data_class.call_method(
            "dataWithBytes:length:", buffer, len(sample_bytes)
        )
        assert data


def test_ns_url(emu_ios, objc):
    with objc.autorelease_pool():
        ns_url_class = objc.find_class("NSURL")
        ns_url_request_class = objc.find_class("NSURLRequest")
        ns_url_session_configuration_class = objc.find_class(
            "NSURLSessionConfiguration"
        )
        ns_url_session_class = objc.find_class("NSURLSession")

        assert (
            ns_url_class
            and ns_url_request_class
            and ns_url_session_configuration_class
            and ns_url_session_class
        )

        url_str = objc.create_ns_string("https://github.com/sledgeh4w/chomper")

        url = ns_url_class.call_method("URLWithString:", url_str)
        assert url

        request = ns_url_request_class.call_method("requestWithURL:", url)
        assert request

        config = ns_url_session_configuration_class.call_method(
            "defaultSessionConfiguration"
        )
        assert config

        session = ns_url_session_class.call_method("sessionWithConfiguration:", config)
        assert session

        task = session.call_method(
            "dataTaskWithRequest:completionHandler:",
            request,
            0,
        )
        assert task

        objc.msg_send(task, "resume")


def test_ns_locale(emu_ios, objc):
    with objc.autorelease_pool():
        ns_locale_class = objc.find_class("NSLocale")
        assert ns_locale_class

        locale = ns_locale_class.call_method("currentLocale")
        assert locale

        preferred_languages = ns_locale_class.call_method("preferredLanguages")
        assert preferred_languages

        preferred_language = preferred_languages.call_method("firstObject")
        assert emu_ios.read_string(objc.msg_send(preferred_language, "UTF8String"))


def test_ns_user_defaults(emu_ios, objc):
    with objc.autorelease_pool():
        ns_user_defaults_class = objc.find_class("NSUserDefaults")
        assert ns_user_defaults_class

        user_defaults = ns_user_defaults_class.call_method("standardUserDefaults")
        assert user_defaults

        key = objc.create_ns_string("AppleLocale")

        apple_locale = user_defaults.call_method("stringForKey:", key)
        assert emu_ios.read_string(apple_locale.call_method("UTF8String"))

        test_key = objc.create_ns_string("TestKey")
        test_value = objc.create_ns_string("TestVey")

        user_defaults.call_method("setObject:forKey:", test_key, test_value)


def test_ns_date(emu_ios, objc):
    with objc.autorelease_pool():
        ns_date_class = objc.find_class("NSDate")
        assert ns_date_class

        date = ns_date_class.call_method("date")
        assert date


def test_ns_date_formatter(emu_ios, objc):
    with objc.autorelease_pool():
        ns_date_class = objc.find_class("NSDate")
        ns_date_formatter_class = objc.find_class("NSDateFormatter")

        assert ns_date_class and ns_date_formatter_class

        date_formatter = ns_date_formatter_class.call_method("alloc")
        assert date_formatter

        date_formatter.call_method("init")

        format_str = objc.create_ns_string("yyyy-MM-dd HH:mm:ss")
        date_formatter.call_method("setDateFormat:", format_str)

        current_date = ns_date_class.call_method("date")
        date_str = date_formatter.call_method("stringFromDate:", current_date)
        assert emu_ios.read_string(date_str.call_method("UTF8String"))

        date = date_formatter.call_method("dateFromString:", date_str)
        assert date


def test_ns_time_zone(emu_ios, objc):
    with objc.autorelease_pool():
        ns_time_zone_class = objc.find_class("NSTimeZone")
        assert ns_time_zone_class

        time_zone = ns_time_zone_class.call_method("defaultTimeZone")
        assert time_zone

        name = time_zone.call_method("name")
        assert emu_ios.read_string(objc.msg_send(name, "UTF8String"))

        time_zone_shanghai = ns_time_zone_class.call_method(
            "timeZoneWithName:",
            objc.create_ns_string("Asia/Shanghai"),
        )
        assert time_zone_shanghai

        ns_time_zone_class.call_method("setDefaultTimeZone:", time_zone_shanghai)


def test_ns_bundle(emu_ios, objc):
    with objc.autorelease_pool():
        ns_bundle_class = objc.find_class("NSBundle")
        assert ns_bundle_class

        bundle = ns_bundle_class.call_method("mainBundle")
        assert bundle

        bundle_path = bundle.call_method("bundlePath")
        assert emu_ios.read_string(bundle_path.call_method("UTF8String"))

        executable_path = bundle.call_method("executablePath")
        assert emu_ios.read_string(executable_path.call_method("UTF8String"))

        info_dictionary = bundle.call_method("infoDictionary")
        assert info_dictionary

        # app_store_receipt_url = bundle.call_method("appStoreReceiptURL")
        # assert app_store_receipt_url


def test_ns_method_signature(emu_ios, objc):
    with objc.autorelease_pool():
        method_signature = objc.msg_send(
            "NSArray",
            "instanceMethodSignatureForSelector:",
            objc.selector("objectAtIndex:"),
        )
        assert method_signature


def test_ns_write_to_file_atomically(emu_ios, objc):
    filepath = "/private/var/tmp/test_ns_write"
    real_path = f"{emu_ios.os.rootfs_path}/{filepath[1:]}"

    with objc.autorelease_pool():
        string = objc.create_ns_string("Mocha")
        tmp_file = objc.create_ns_string(filepath)

        result = objc.msg_send(string, "writeToFile:atomically:", tmp_file, 1)
        assert result

    os.remove(real_path)


def test_ns_file_manager(emu_ios, objc):
    with objc.autorelease_pool():
        ns_file_manager_class = objc.find_class("NSFileManager")
        assert ns_file_manager_class

        system_version_path = objc.create_ns_string(
            "/System/Library/CoreServices/SystemVersion.plist"
        )

        file_manager = ns_file_manager_class.call_method("defaultManager")
        assert file_manager

        exists = file_manager.call_method("fileExistsAtPath:", system_version_path)
        assert exists

        attributes = file_manager.call_method(
            "attributesOfItemAtPath:error:",
            system_version_path,
            0,
        )
        assert attributes

        path = objc.create_ns_string("/System/Library")
        directory_contents = file_manager.call_method("directoryContentsAtPath:", path)
        assert directory_contents

        identity_token = file_manager.call_method("ubiquityIdentityToken")
        assert identity_token


def test_ui_device(emu_ios, objc):
    with objc.autorelease_pool():
        ui_device_class = objc.find_class("UIDevice")
        assert ui_device_class

        device = ui_device_class.call_method("currentDevice")
        assert device

        system_name = device.call_method("systemName")
        assert system_name

        system_version = device.call_method("systemVersion")
        assert system_version

        device.call_method("setBatteryMonitoringEnabled:", 1)

        vendor_identifier = device.call_method("identifierForVendor")
        assert vendor_identifier


def test_ui_screen(emu_ios, objc):
    with objc.autorelease_pool():
        ui_screen_class = objc.find_class("UIScreen")
        assert ui_screen_class

        screen = ui_screen_class.call_method("mainScreen")
        assert screen

        brightness = screen.call_method("brightness")
        assert brightness


def test_ui_font(emu_ios, objc):
    with objc.autorelease_pool():
        ui_font_class = objc.find_class("UIFont")
        assert ui_font_class

        family_names = ui_font_class.call_method("familyNames")
        assert family_names


def test_ui_pasteboard(emu_ios, objc):
    with objc.autorelease_pool():
        ui_pasteboard_class = objc.find_class("UIPasteboard")
        assert ui_pasteboard_class

        pasteboard = ui_pasteboard_class.call_method("generalPasteboard")
        assert pasteboard

        name = objc.create_ns_string("Mocha")

        pasteboard_with_name = ui_pasteboard_class.call_method(
            "pasteboardWithName:create:",
            name,
            1,
        )
        assert pasteboard_with_name


def test_ca_display(emu_ios, objc):
    with objc.autorelease_pool():
        ca_display_class = objc.find_class("CADisplay")
        assert ca_display_class

        display = ca_display_class.call_method("mainDisplay")
        assert display


def test_ct_telephony_network_info(emu_ios, objc):
    with objc.autorelease_pool():
        ct_telephony_network_info_class = objc.find_class("CTTelephonyNetworkInfo")
        assert ct_telephony_network_info_class

        network_info = ct_telephony_network_info_class.call_method("alloc")
        assert network_info

        network_info.call_method("init")

        network_info.call_method("currentRadioAccessTechnology")


def test_ct_cellular_data(emu_ios, objc):
    with objc.autorelease_pool():
        ct_cellular_data_class = objc.find_class("CTCellularData")
        assert ct_cellular_data_class

        cellular_data = ct_cellular_data_class.call_method("alloc")
        assert cellular_data

        cellular_data.call_method("init")

        # state = objc.msg_send(cellular_data, "restrictedState")
        # assert state


def test_ls_application_workspace(emu_ios, objc):
    with objc.autorelease_pool():
        ls_application_workspace_class = objc.find_class("LSApplicationWorkspace")
        assert ls_application_workspace_class

        workspace = ls_application_workspace_class.call_method("defaultWorkspace")
        assert workspace

        plugins = objc.msg_send(workspace, "installedPlugins")
        assert plugins


def test_cl_location_manager(emu_ios, objc):
    with objc.autorelease_pool():
        cl_location_manager_class = objc.find_class("CLLocationManager")
        assert cl_location_manager_class

        location_manager = cl_location_manager_class.call_method("alloc")
        assert location_manager

        location_manager.call_method("init")

        cl_location_manager_class.call_method("locationServicesEnabled")

        cl_location_manager_class.call_method("authorizationStatus")


def test_ns_log(emu_ios, objc):
    with objc.autorelease_pool():
        msg = objc.create_ns_string("test")

        emu_ios.call_symbol("_NSLog", msg.value)


def test_cf_network(emu_ios, objc):
    with objc.autorelease_pool():
        result = emu_ios.call_symbol("_CFNetworkCopySystemProxySettings")
        assert result

        result = emu_ios.call_symbol("__CFNetworkCopyPreferredLanguageCode")
        assert result


def test_cf_run_loop(emu_ios, objc):
    with objc.autorelease_pool():
        run_loop = emu_ios.call_symbol("_CFRunLoopGetMain")
        assert run_loop


def test_system_configuration(emu_ios, objc):
    with emu_ios.memory_scope() as mem, objc.autorelease_pool():
        name_ptr = mem.create_string("apple.com")
        flags_ptr = mem.create_buffer(8)

        reachability = emu_ios.call_symbol(
            "_SCNetworkReachabilityCreateWithName",
            0,
            name_ptr,
        )
        assert reachability

        result = emu_ios.call_symbol(
            "_SCNetworkReachabilityGetFlags",
            reachability,
            flags_ptr,
        )
        assert result

        interface_name = objc.create_cf_string("en0")
        emu_ios.call_symbol("_CNCopyCurrentNetworkInfo", interface_name)


def test_dispatch_semaphore(emu_ios):
    semaphore = emu_ios.call_symbol("_dispatch_semaphore_create", 0)

    result = emu_ios.call_symbol("_dispatch_semaphore_signal", semaphore)
    assert result == 0

    result = emu_ios.call_symbol("_dispatch_semaphore_wait", semaphore, -1)
    assert result == 0

    emu_ios.call_symbol("_dispatch_release", semaphore)


def test_clock(emu_ios):
    clock_port = emu_ios.ios_os.MACH_PORT_CLOCK

    with emu_ios.memory_scope() as mem:
        cur_time_ptr = mem.create_buffer(sizeof(MachTimespec))

        result = emu_ios.call_symbol("_clock_get_time", clock_port, cur_time_ptr)
        assert result == 0


def test_clonefile(emu_ios):
    work_dir = "/System/Library/CoreServices"
    emu_ios.os.set_working_dir(work_dir)

    src = "SystemVersion.plist"
    dst = "SystemVersion.plist.bak"

    dst_path = os.path.join(emu_ios.os.rootfs_path, work_dir.lstrip("/"), dst)
    if os.path.exists(dst_path):
        os.remove(dst_path)

    with emu_ios.memory_scope() as mem:
        src_str = mem.create_string(src)
        dst_str = mem.create_string(dst)

        emu_ios.call_symbol("_clonefile", src_str, dst_str, 0)

        assert os.path.exists(dst_path)


def test_mach_ports(emu_ios):
    with emu_ios.memory_scope() as mem:
        port_ptr = mem.create_buffer(4)

        port = emu_ios.call_symbol("_mach_host_self")
        assert port == emu_ios.ios_os.MACH_PORT_HOST

        port = emu_ios.call_symbol("_mach_task_self")
        assert port == emu_ios.ios_os.MACH_PORT_TASK

        port = emu_ios.call_symbol("_mach_thread_self")
        assert port == emu_ios.ios_os.MACH_PORT_THREAD

        bootstrap_port = emu_ios.find_symbol("_bootstrap_port")
        assert (
            emu_ios.read_u32(bootstrap_port.address)
            == emu_ios.ios_os.MACH_PORT_BOOTSTRAP
        )

        emu_ios.call_symbol(
            "_host_get_special_port",
            emu_ios.ios_os.MACH_PORT_HOST,
            0,
            const.HOST_PORT,
            port_ptr,
        )
        assert emu_ios.read_u32(port_ptr) == emu_ios.ios_os.MACH_PORT_HOST

        emu_ios.call_symbol(
            "_task_get_special_port",
            emu_ios.ios_os.MACH_PORT_TASK,
            const.TASK_BOOTSTRAP_PORT,
            port_ptr,
        )
        assert emu_ios.read_u32(port_ptr) == emu_ios.ios_os.MACH_PORT_BOOTSTRAP

        io_master_ptr = mem.create_buffer(4)
        emu_ios.call_symbol(
            "_host_get_io_master", emu_ios.ios_os.MACH_PORT_HOST, io_master_ptr
        )
        assert emu_ios.read_u32(io_master_ptr) == emu_ios.ios_os.MACH_PORT_IO_MASTER

        port = emu_ios.call_symbol("__os_trace_create_debug_control_port")
        assert port

        masks_ptr = mem.create_buffer(4 * 14)
        masks_cnt_ptr = mem.create_buffer(4)
        handlers_ptr = mem.create_buffer(4 * 14)
        behaviors_ptr = mem.create_buffer(4 * 14)
        flavors_ptr = mem.create_buffer(4 * 14)

        result = emu_ios.call_symbol(
            "_task_get_exception_ports",
            emu_ios.ios_os.MACH_PORT_TASK,
            0,
            masks_ptr,
            masks_cnt_ptr,
            handlers_ptr,
            behaviors_ptr,
            flavors_ptr,
        )
        assert result == 0


def test_xpc_connection(emu_ios):
    service = emu_ios.call_symbol(
        "_xpc_connection_create_mach_service",
        emu_ios.create_string("com.apple.lsd.advertisingidentifiers"),
        0,
        const.XPC_CONNECTION_MACH_SERVICE_LISTENER,
    )
    assert service


def test_resolv(emu_ios):
    with emu_ios.memory_scope() as mem:
        res = mem.create_buffer(552)

        result = emu_ios.call_symbol("_res_9_ninit", res)
        assert result == 0
