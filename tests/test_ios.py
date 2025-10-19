from ctypes import sizeof

from chomper.os.ios import const
from chomper.os.ios.structs import MachTimespec

from .utils import alloc_vars


def test_ns_number(emu_ios, objc):
    with objc.autorelease_pool():
        value = 1

        number = objc.msg_send("NSNumber", "numberWithInteger:", value)
        assert number

        raw_value = objc.msg_send(number, "intValue")
        assert value == raw_value


def test_ns_string(emu_ios, objc):
    with objc.autorelease_pool():
        string = objc.msg_send("NSString", "stringWithUTF8String:", "chomper")
        assert string


def test_ns_mutable_string(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        string = objc.msg_send("NSMutableString", "string")

        objc.msg_send(string, "setString:", objc.create_ns_string(sample_str))
        raw_string = objc.msg_send(string, "UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str

        objc.msg_send(string, "appendString:", objc.create_ns_string(sample_str))
        raw_string = objc.msg_send(string, "UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str * 2


def test_ns_array(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        array = objc.msg_send(
            "NSArray", "arrayWithObjects:", objc.create_ns_string(sample_str)
        )
        assert array

        first_object = objc.msg_send(array, "objectAtIndex:", 0)
        raw_string = objc.msg_send(first_object, "UTF8String")
        assert emu_ios.read_string(raw_string) == sample_str

        description = objc.msg_send(array, "description")
        assert description


def test_ns_mutable_array(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        array = objc.msg_send("NSMutableArray", "array")
        assert array

        objc.msg_send(array, "addObject:", objc.create_ns_string(sample_str))

        first_object = objc.msg_send(array, "objectAtIndex:", 0)
        raw_string = objc.msg_send(first_object, "UTF8String")
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

        value2 = objc.msg_send(dictionary, "objectForKey:", key)
        raw_string = objc.msg_send(value2, "UTF8String")
        assert emu_ios.read_string(raw_string) == sample_value

        description = objc.msg_send(dictionary, "description")
        assert description


def test_ns_mutable_dictionary(emu_ios, objc):
    with objc.autorelease_pool():
        sample_key = "name"
        sample_value = "chomper"

        dictionary = objc.msg_send("NSMutableDictionary", "dictionary")
        assert dictionary

        key = objc.create_ns_string(sample_key)
        value = objc.create_ns_string(sample_value)

        objc.msg_send(dictionary, "setObject:forKey:", value, key)

        value2 = objc.msg_send(dictionary, "objectForKey:", key)
        raw_string = objc.msg_send(value2, "UTF8String")
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

        task = objc.msg_send(
            session, "dataTaskWithRequest:completionHandler:", request, 0
        )
        assert task

        objc.msg_send(task, "resume")


def test_ns_locale(emu_ios, objc):
    with objc.autorelease_pool():
        locale = objc.msg_send("NSLocale", "currentLocale")
        assert locale

        preferred_languages = objc.msg_send("NSLocale", "preferredLanguages")
        assert preferred_languages

        preferred_language = objc.msg_send(preferred_languages, "firstObject")
        raw_string = objc.msg_send(preferred_language, "UTF8String")
        assert emu_ios.read_string(raw_string)


def test_ns_user_defaults(emu_ios, objc):
    with objc.autorelease_pool():
        user_defaults = objc.msg_send("NSUserDefaults", "standardUserDefaults")
        assert user_defaults

        key = objc.create_ns_string("AppleLocale")

        apple_locale = objc.msg_send(user_defaults, "stringForKey:", key)
        raw_string = objc.msg_send(apple_locale, "UTF8String")
        assert emu_ios.read_string(raw_string)

        test_key = objc.create_ns_string("TestKey")
        test_value = objc.create_ns_string("TestVey")

        objc.msg_send(user_defaults, "setObject:forKey:", test_key, test_value)


def test_ns_date(emu_ios, objc):
    with objc.autorelease_pool():
        date = objc.msg_send("NSDate", "date")
        assert date


def test_ns_date_formatter(emu_ios, objc):
    with objc.autorelease_pool():
        date_formatter = objc.msg_send("NSDateFormatter", "alloc")
        date_formatter = objc.msg_send(date_formatter, "init")
        assert date_formatter

        format_str = objc.create_ns_string("yyyy-MM-dd HH:mm:ss")
        objc.msg_send(date_formatter, "setDateFormat:", format_str)

        current_date = objc.msg_send("NSDate", "date")

        date_str = objc.msg_send(date_formatter, "stringFromDate:", current_date)
        raw_string = objc.msg_send(date_str, "UTF8String")
        assert emu_ios.read_string(raw_string)

        date = objc.msg_send(date_formatter, "dateFromString:", date_str)
        assert date


def test_ns_time_zone(emu_ios, objc):
    with objc.autorelease_pool():
        time_zone = objc.msg_send("NSTimeZone", "defaultTimeZone")
        assert time_zone

        name = objc.msg_send(time_zone, "name")
        raw_string = objc.msg_send(name, "UTF8String")
        assert emu_ios.read_string(raw_string)

        time_zone_shanghai = objc.msg_send(
            "NSTimeZone", "timeZoneWithName:", objc.create_ns_string("Asia/Shanghai")
        )
        assert time_zone_shanghai

        objc.msg_send("NSTimeZone", "setDefaultTimeZone:", time_zone_shanghai)


def test_ns_bundle(emu_ios, objc):
    with objc.autorelease_pool():
        main_bundle = objc.msg_send("NSBundle", "mainBundle")
        assert main_bundle

        bundle_path = objc.msg_send(main_bundle, "bundlePath")
        raw_string = objc.msg_send(bundle_path, "UTF8String")
        assert emu_ios.read_string(raw_string)

        executable_path = objc.msg_send(main_bundle, "executablePath")
        raw_string = objc.msg_send(executable_path, "UTF8String")
        assert emu_ios.read_string(raw_string)

        info_dictionary = objc.msg_send(main_bundle, "infoDictionary")
        assert info_dictionary


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

        exists = objc.msg_send(file_manager, "fileExistsAtPath:", system_version_path)
        assert exists

        attributes = objc.msg_send(
            file_manager, "attributesOfItemAtPath:error:", system_version_path, 0
        )
        assert attributes

        path = objc.create_ns_string("/System/Library")
        directory_contents = objc.msg_send(
            file_manager, "directoryContentsAtPath:", path
        )
        assert directory_contents


def test_ui_device(emu_ios, objc):
    with objc.autorelease_pool():
        device = objc.msg_send("UIDevice", "currentDevice")
        assert device

        system_version = objc.msg_send(device, "systemVersion")
        assert system_version

        objc.msg_send(device, "setBatteryMonitoringEnabled:", 1)

        vendor_identifier = objc.msg_send(device, "identifierForVendor")
        assert vendor_identifier


def test_ui_screen(emu_ios, objc):
    with objc.autorelease_pool():
        screen = objc.msg_send("UIScreen", "mainScreen")
        assert screen


def test_ca_display(emu_ios, objc):
    with objc.autorelease_pool():
        display = objc.msg_send("CADisplay", "mainDisplay")
        assert display


# def test_ct_telephony_network_info(emu_ios, objc):
#     with objc.autorelease_pool():
#         network_info = objc.msg_send("CTTelephonyNetworkInfo", "new")
#         assert network_info
#
#         radio_access_technology = objc.msg_send(
#             network_info,
#             "currentRadioAccessTechnology",
#         )
#         assert radio_access_technology


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


def test_sc_network_reachability(emu_ios, objc):
    with objc.autorelease_pool():
        name = "apple.com"

        with alloc_vars(emu_ios, name, 8) as (name_ptr, flags):
            reachability = emu_ios.call_symbol(
                "_SCNetworkReachabilityCreateWithName", 0, name_ptr
            )
            assert reachability

            result = emu_ios.call_symbol(
                "_SCNetworkReachabilityGetFlags", reachability, flags
            )
            assert result


def test_dispatch_semaphore(emu_ios):
    semaphore = emu_ios.call_symbol("_dispatch_semaphore_create", 0)

    result = emu_ios.call_symbol("_dispatch_semaphore_signal", semaphore)
    assert result == 0

    result = emu_ios.call_symbol("_dispatch_semaphore_wait", semaphore, -1)
    assert result == 0

    emu_ios.call_symbol("_dispatch_release", semaphore)


def test_clock(emu_ios):
    clock_port = emu_ios.ios_os.MACH_PORT_CLOCK

    with alloc_vars(emu_ios, sizeof(MachTimespec)) as (cur_time_buf,):
        result = emu_ios.call_symbol("_clock_get_time", clock_port, cur_time_buf)
        assert result == 0


def test_mach_ports(emu_ios):
    with alloc_vars(emu_ios, 4) as (port_buf,):
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

        result = emu_ios.call_symbol(
            "_host_get_special_port",
            emu_ios.ios_os.MACH_PORT_HOST,
            0,
            const.HOST_PORT,
            port_buf,
        )
        assert result == 0 and emu_ios.read_u32(port_buf)

        result = emu_ios.call_symbol(
            "_task_get_special_port",
            emu_ios.ios_os.MACH_PORT_TASK,
            const.TASK_BOOTSTRAP_PORT,
            port_buf,
        )
        assert result == 0 and emu_ios.read_u32(port_buf)


def test_xpc_connection(emu_ios):
    service = emu_ios.call_symbol(
        "_xpc_connection_create_mach_service",
        emu_ios.create_string("com.apple.lsd.advertisingidentifiers"),
        0,
        const.XPC_CONNECTION_MACH_SERVICE_LISTENER,
    )
    assert service
