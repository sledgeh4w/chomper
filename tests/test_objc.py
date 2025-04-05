from chomper.utils import pyobj2nsobj


def test_ns_string(emu_ios, objc):
    with objc.autorelease_pool():
        string = objc.msg_send("NSString", "stringWithUTF8String:", "chomper")
        assert string


def test_ns_mutable_string(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        string = objc.msg_send("NSMutableString", "string")

        objc.msg_send(string, "setString:", pyobj2nsobj(emu_ios, sample_str))
        raw_string = objc.msg_send(string, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string) == sample_str

        objc.msg_send(string, "appendString:", pyobj2nsobj(emu_ios, sample_str))
        raw_string = objc.msg_send(string, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string) == sample_str * 2


def test_ns_array(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        array = objc.msg_send(
            "NSArray", "arrayWithObjects:", pyobj2nsobj(emu_ios, sample_str)
        )
        assert array

        first_object = objc.msg_send(array, "objectAtIndex:", 0)
        raw_string = objc.msg_send(first_object, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string) == sample_str

        description = objc.msg_send(array, "description")
        assert description


def test_ns_mutable_array(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        array = objc.msg_send("NSMutableArray", "array")
        assert array

        objc.msg_send(array, "addObject:", pyobj2nsobj(emu_ios, sample_str))

        first_object = objc.msg_send(array, "objectAtIndex:", 0)
        raw_string = objc.msg_send(first_object, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string) == sample_str


def test_ns_dictionary(emu_ios, objc):
    with objc.autorelease_pool():
        sample_key = "chomper"
        sample_value = "1"

        key = pyobj2nsobj(emu_ios, sample_key)
        value = pyobj2nsobj(emu_ios, sample_value)

        dictionary = objc.msg_send(
            "NSDictionary", "dictionaryWithObjectsAndKeys:", value, va_list=(key,)
        )
        assert dictionary

        value2 = objc.msg_send(dictionary, "objectForKey:", key)
        raw_string = objc.msg_send(value2, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string) == sample_value

        description = objc.msg_send(dictionary, "description")
        assert description


def test_ns_mutable_dictionary(emu_ios, objc):
    with objc.autorelease_pool():
        sample_key = "chomper"
        sample_value = "1"

        dictionary = objc.msg_send("NSMutableDictionary", "dictionary")
        assert dictionary

        key = pyobj2nsobj(emu_ios, sample_key)
        value = pyobj2nsobj(emu_ios, sample_value)

        objc.msg_send(dictionary, "setObject:forKey:", value, key)

        value2 = objc.msg_send(dictionary, "objectForKey:", key)
        raw_string = objc.msg_send(value2, "cStringUsingEncoding:", 4)
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
        url_str = objc.msg_send(
            "NSString", "stringWithUTF8String:", "https://github.com/sledgeh4w/chomper"
        )

        url = objc.msg_send("NSURL", "URLWithString:", url_str)
        assert url


def test_ns_request(emu_ios, objc):
    with objc.autorelease_pool():
        url_str = objc.msg_send(
            "NSString", "stringWithUTF8String:", "https://github.com/sledgeh4w/chomper"
        )
        url = objc.msg_send("NSURL", "URLWithString:", url_str)

        request = objc.msg_send("NSMutableURLRequest", "requestWithURL:", url)
        assert request


def test_ns_locale(emu_ios, objc):
    with objc.autorelease_pool():
        locale = objc.msg_send("NSLocale", "currentLocale")
        assert locale

        preferred_languages = objc.msg_send("NSLocale", "preferredLanguages")
        assert preferred_languages

        preferred_language = objc.msg_send(preferred_languages, "firstObject")
        raw_string = objc.msg_send(preferred_language, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string)


def test_ns_user_defaults(emu_ios, objc):
    with objc.autorelease_pool():
        user_defaults = objc.msg_send("NSUserDefaults", "standardUserDefaults")
        assert user_defaults

        key = pyobj2nsobj(emu_ios, "AppleLocale")

        apple_locale = objc.msg_send(user_defaults, "stringForKey:", key)
        raw_string = objc.msg_send(apple_locale, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string)

        test_key = pyobj2nsobj(emu_ios, "TestKey")
        test_value = pyobj2nsobj(emu_ios, "TestVey")

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

        format_str = pyobj2nsobj(emu_ios, "yyyy-MM-dd HH:mm:ss")
        objc.msg_send(date_formatter, "setDateFormat:", format_str)

        current_date = objc.msg_send("NSDate", "date")

        date_str = objc.msg_send(date_formatter, "stringFromDate:", current_date)
        raw_string = objc.msg_send(date_str, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string)

        date = objc.msg_send(date_formatter, "dateFromString:", date_str)
        assert date


def test_ns_time_zone(emu_ios, objc):
    with objc.autorelease_pool():
        time_zone = objc.msg_send("NSTimeZone", "defaultTimeZone")
        assert time_zone

        name = objc.msg_send(time_zone, "name")
        raw_string = objc.msg_send(name, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string)

        time_zone_shanghai = objc.msg_send(
            "NSTimeZone", "timeZoneWithName:", pyobj2nsobj(emu_ios, "Asia/Shanghai")
        )
        assert time_zone_shanghai

        objc.msg_send("NSTimeZone", "setDefaultTimeZone:", time_zone_shanghai)


def test_ns_bundle(emu_ios, objc):
    with objc.autorelease_pool():
        main_bundle = objc.msg_send("NSBundle", "mainBundle")
        assert main_bundle

        bundle_path = objc.msg_send(main_bundle, "bundlePath")
        raw_string = objc.msg_send(bundle_path, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string)

        executable_path = objc.msg_send(main_bundle, "executablePath")
        raw_string = objc.msg_send(executable_path, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(raw_string)

        info_dictionary = objc.msg_send(main_bundle, "infoDictionary")
        assert info_dictionary


def test_ns_method_signature(emu_ios, objc):
    with objc.autorelease_pool():
        method_signature = objc.msg_send(
            "NSArray",
            "instanceMethodSignatureForSelector:",
            objc.get_sel("objectAtIndex:"),
        )
        assert method_signature


def test_ns_write_to_file_atomically(emu_ios, objc):
    with objc.autorelease_pool():
        string = objc.msg_send("NSString", "stringWithUTF8String:", "chomper")
        filename = objc.msg_send("NSString", "stringWithUTF8String:", "test_write")

        result = objc.msg_send(string, "writeToFile:atomically:", filename, 1)
        assert result


def test_ns_url_session(emu_ios, objc):
    with objc.autorelease_pool():
        config = objc.msg_send(
            "NSURLSessionConfiguration", "defaultSessionConfiguration"
        )
        assert config

        session = objc.msg_send("NSURLSession", "sessionWithConfiguration:", config)
        assert session


def test_ns_file_manager(emu_ios, objc):
    with objc.autorelease_pool():
        file_manager = objc.msg_send("NSFileManager", "defaultManager")
        assert file_manager

        path = pyobj2nsobj(emu_ios, "/System/Library/CoreServices/SystemVersion.plist")
        attributes = objc.msg_send(
            file_manager, "attributesOfItemAtPath:error:", path, 0
        )
        assert attributes

        path = pyobj2nsobj(emu_ios, "/System/Library")
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


def test_cf_network(emu_ios, objc):
    with objc.autorelease_pool():
        system_proxy_settings = emu_ios.call_symbol("_CFNetworkCopySystemProxySettings")
        assert system_proxy_settings
