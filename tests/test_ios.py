import os
from ctypes import sizeof

from chomper.os.ios import const
from chomper.os.ios.structs import MachTimespec


def test_ns_number(emu_ios, objc):
    with objc.autorelease_pool():
        value = 1

        number = objc.msg_send("NSNumber", "numberWithInteger:", value)
        assert number

        raw_value = number.call_method("intValue")
        assert value == raw_value


def test_ns_string(emu_ios, objc):
    with objc.autorelease_pool():
        string = objc.msg_send("NSString", "stringWithUTF8String:", "chomper")
        assert string


def test_ns_mutable_string(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        string = objc.msg_send("NSMutableString", "string")

        string.call_method("setString:", objc.create_ns_string(sample_str))
        raw_string = string.call_method("UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str

        string.call_method("appendString:", objc.create_ns_string(sample_str))
        raw_string = string.call_method("UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str * 2


def test_ns_array(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        array = objc.msg_send(
            "NSArray", "arrayWithObjects:", objc.create_ns_string(sample_str)
        )
        assert array

        first_object = array.call_method("objectAtIndex:", 0)
        raw_string = objc.msg_send(first_object, "UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str

        description = array.call_method("description")
        assert description


def test_ns_mutable_array(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        array = objc.msg_send("NSMutableArray", "array")
        assert array

        array.call_method("addObject:", objc.create_ns_string(sample_str))

        first_object = array.call_method("objectAtIndex:", 0)
        raw_string = first_object.call_method("UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str


def test_ns_dictionary(emu_ios, objc):
    with objc.autorelease_pool():
        sample_key = "name"
        sample_value = "chomper"

        key = objc.create_ns_string(sample_key)
        value = objc.create_ns_string(sample_value)

        dictionary = objc.msg_send(
            "NSDictionary", "dictionaryWithObjectsAndKeys:", value, va_list=(key,)
        )
        assert dictionary

        value2 = dictionary.call_method("objectForKey:", key)
        raw_string = value2.call_method("UTF8String")
        assert emu_ios.read_string(raw_string) == sample_value

        description = dictionary.call_method("description")
        assert description


def test_ns_mutable_dictionary(emu_ios, objc):
    with objc.autorelease_pool():
        sample_key = "name"
        sample_value = "chomper"

        dictionary = objc.msg_send("NSMutableDictionary", "dictionary")
        assert dictionary

        key = objc.create_ns_string(sample_key)
        value = objc.create_ns_string(sample_value)

        dictionary.call_method("setObject:forKey:", value, key)

        value2 = dictionary.call_method("objectForKey:", key)
        raw_string = value2.call_method("UTF8String")
        assert emu_ios.read_string(raw_string) == sample_value


def test_ns_data(emu_ios, objc):
    with objc.autorelease_pool():
        sample_bytes = b"chomper"

        buffer = emu_ios.create_buffer(len(sample_bytes))
        emu_ios.write_bytes(buffer, sample_bytes)

        data = objc.msg_send(
            "NSData", "dataWithBytes:length:", buffer, len(sample_bytes)
        )
        assert data


def test_ns_data_with_large_size(emu_ios, objc):
    """When the size of `NSData` exceeds 64k, `vm_allocate` will be called."""
    with objc.autorelease_pool():
        sample_bytes = bytes(1024 * 64)

        buffer = emu_ios.create_buffer(len(sample_bytes))
        emu_ios.write_bytes(buffer, sample_bytes)

        data = objc.msg_send(
            "NSData", "dataWithBytes:length:", buffer, len(sample_bytes)
        )
        assert data


def test_ns_url(emu_ios, objc):
    with objc.autorelease_pool():
        url_str = objc.create_ns_string("https://github.com/sledgeh4w/chomper")

        url = objc.msg_send("NSURL", "URLWithString:", url_str)
        assert url

        request = objc.msg_send("NSURLRequest", "requestWithURL:", url)
        assert request

        config = objc.msg_send(
            "NSURLSessionConfiguration", "defaultSessionConfiguration"
        )
        assert config

        session = objc.msg_send("NSURLSession", "sessionWithConfiguration:", config)
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
        locale = objc.msg_send("NSLocale", "currentLocale")
        assert locale

        preferred_languages = objc.msg_send("NSLocale", "preferredLanguages")
        assert preferred_languages

        preferred_language = preferred_languages.call_method("firstObject")
        assert emu_ios.read_string(objc.msg_send(preferred_language, "UTF8String"))


def test_ns_user_defaults(emu_ios, objc):
    with objc.autorelease_pool():
        user_defaults = objc.msg_send("NSUserDefaults", "standardUserDefaults")
        assert user_defaults

        key = objc.create_ns_string("AppleLocale")

        apple_locale = user_defaults.call_method("stringForKey:", key)
        assert emu_ios.read_string(apple_locale.call_method("UTF8String"))

        test_key = objc.create_ns_string("TestKey")
        test_value = objc.create_ns_string("TestVey")

        user_defaults.call_method("setObject:forKey:", test_key, test_value)


def test_ns_date(emu_ios, objc):
    with objc.autorelease_pool():
        date = objc.msg_send("NSDate", "date")
        assert date


def test_ns_date_formatter(emu_ios, objc):
    with objc.autorelease_pool():
        date_formatter = objc.msg_send("NSDateFormatter", "alloc")
        date_formatter.call_method("init")
        assert date_formatter

        format_str = objc.create_ns_string("yyyy-MM-dd HH:mm:ss")
        date_formatter.call_method("setDateFormat:", format_str)

        current_date = objc.msg_send("NSDate", "date")
        date_str = date_formatter.call_method("stringFromDate:", current_date)
        assert emu_ios.read_string(date_str.call_method("UTF8String"))

        date = date_formatter.call_method("dateFromString:", date_str)
        assert date


def test_ns_time_zone(emu_ios, objc):
    with objc.autorelease_pool():
        time_zone = objc.msg_send("NSTimeZone", "defaultTimeZone")
        assert time_zone

        name = time_zone.call_method("name")
        assert emu_ios.read_string(objc.msg_send(name, "UTF8String"))

        time_zone_shanghai = objc.msg_send(
            "NSTimeZone", "timeZoneWithName:", objc.create_ns_string("Asia/Shanghai")
        )
        assert time_zone_shanghai

        objc.msg_send("NSTimeZone", "setDefaultTimeZone:", time_zone_shanghai)


def test_ns_bundle(emu_ios, objc):
    with objc.autorelease_pool():
        bundle = objc.msg_send("NSBundle", "mainBundle")
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
    with objc.autorelease_pool():
        string = objc.create_ns_string("chomper")
        filename = objc.create_ns_string("test_ns_write_atomically")

        result = objc.msg_send(string, "writeToFile:atomically:", filename, 1)
        assert result


def test_ns_file_manager(emu_ios, objc):
    with objc.autorelease_pool():
        system_version_path = objc.create_ns_string(
            "/System/Library/CoreServices/SystemVersion.plist"
        )

        file_manager = objc.msg_send("NSFileManager", "defaultManager")
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
        device = objc.msg_send("UIDevice", "currentDevice")
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
        screen = objc.msg_send("UIScreen", "mainScreen")
        assert screen

        brightness = screen.call_method("brightness")
        assert brightness


def test_ui_font(emu_ios, objc):
    with objc.autorelease_pool():
        family_names = objc.msg_send("UIFont", "familyNames")
        assert family_names


def test_ca_display(emu_ios, objc):
    with objc.autorelease_pool():
        display = objc.msg_send("CADisplay", "mainDisplay")
        assert display


def test_ct_telephony_network_info(emu_ios, objc):
    with objc.autorelease_pool():
        network_info = objc.msg_send("CTTelephonyNetworkInfo", "alloc")
        assert network_info

        network_info.call_method("init")

        network_info.call_method("currentRadioAccessTechnology")


def test_ct_cellular_data(emu_ios, objc):
    with objc.autorelease_pool():
        cellular_data = objc.msg_send("CTCellularData", "alloc")
        assert cellular_data

        cellular_data.call_method("init")

        # state = objc.msg_send(cellular_data, "restrictedState")
        # assert state


def test_ls_application_workspace(emu_ios, objc):
    with objc.autorelease_pool():
        workspace = objc.msg_send("LSApplicationWorkspace", "defaultWorkspace")

        plugins = objc.msg_send(workspace, "installedPlugins")
        assert plugins


def test_cl_location_manager(emu_ios, objc):
    with objc.autorelease_pool():
        objc.msg_send("CLLocationManager", "locationServicesEnabled")

        objc.msg_send(
            "CLLocationManager",
            "_authorizationStatusForBundleIdentifier:bundle:",
            0,
            0,
        )


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
    with emu_ios.mem_context() as ctx, objc.autorelease_pool():
        name = "apple.com"

        name_ptr = ctx.create_string(name)
        flags_ptr = ctx.create_buffer(8)

        reachability = emu_ios.call_symbol(
            "_SCNetworkReachabilityCreateWithName", 0, name_ptr
        )
        assert reachability

        result = emu_ios.call_symbol(
            "_SCNetworkReachabilityGetFlags", reachability, flags_ptr
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

    with emu_ios.mem_context() as ctx:
        cur_time_ptr = ctx.create_buffer(sizeof(MachTimespec))

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

    with emu_ios.mem_context() as ctx:
        src_str = ctx.create_string(src)
        dst_str = ctx.create_string(dst)

        emu_ios.call_symbol("_clonefile", src_str, dst_str, 0)

        assert os.path.exists(dst_path)


def test_mach_ports(emu_ios):
    with emu_ios.mem_context() as ctx:
        port_ptr = ctx.create_buffer(4)

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

        io_master_ptr = ctx.create_buffer(4)
        emu_ios.call_symbol(
            "_host_get_io_master", emu_ios.ios_os.MACH_PORT_HOST, io_master_ptr
        )
        assert emu_ios.read_u32(io_master_ptr) == emu_ios.ios_os.MACH_PORT_IO_MASTER

        port = emu_ios.call_symbol("__os_trace_create_debug_control_port")
        assert port

        masks_ptr = ctx.create_buffer(4 * 14)
        masks_cnt_ptr = ctx.create_buffer(4)
        handlers_ptr = ctx.create_buffer(4 * 14)
        behaviors_ptr = ctx.create_buffer(4 * 14)
        flavors_ptr = ctx.create_buffer(4 * 14)

        result = emu_ios.call_symbol(
            "_task_get_exception_ports",
            emu_ios.ios_os.MACH_PORT_TASK,
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
    with emu_ios.mem_context() as ctx:
        res = ctx.create_buffer(552)

        result = emu_ios.call_symbol("_res_9_ninit", res)
        assert result == 0
