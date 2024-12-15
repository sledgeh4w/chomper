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
        c_str = objc.msg_send(string, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str) == sample_str

        objc.msg_send(string, "appendString:", pyobj2nsobj(emu_ios, sample_str))
        c_str = objc.msg_send(string, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str) == sample_str * 2


def test_ns_array(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        array = objc.msg_send(
            "NSArray", "arrayWithObjects:", pyobj2nsobj(emu_ios, sample_str)
        )
        assert array

        first_object = objc.msg_send(array, "objectAtIndex:", 0)
        c_str = objc.msg_send(first_object, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str) == sample_str

        description = objc.msg_send(array, "description")
        assert description


def test_ns_mutable_array(emu_ios, objc):
    with objc.autorelease_pool():
        sample_str = "chomper"

        array = objc.msg_send("NSMutableArray", "array")
        assert array

        objc.msg_send(array, "addObject:", pyobj2nsobj(emu_ios, sample_str))

        first_object = objc.msg_send(array, "objectAtIndex:", 0)
        c_str = objc.msg_send(first_object, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str) == sample_str


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
        c_str = objc.msg_send(value2, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str) == sample_value

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
        c_str = objc.msg_send(value2, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str) == sample_value


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

        url = objc.msg_send("NSURL", "alloc")
        objc.msg_send(url, "initWithString:", url_str)
        assert url


def test_ns_request(emu_ios, objc):
    with objc.autorelease_pool():
        url_str = objc.msg_send(
            "NSString", "stringWithUTF8String:", "https://github.com/sledgeh4w/chomper"
        )

        url = objc.msg_send("NSURL", "alloc")
        objc.msg_send(url, "initWithString:", url_str)

        request = objc.msg_send("NSMutableURLRequest", "requestWithURL:", url)
        assert request


def test_ns_locale(emu_ios, objc):
    with objc.autorelease_pool():
        preferred_languages = objc.msg_send("NSLocale", "preferredLanguages")
        assert preferred_languages

        preferred_language = objc.msg_send(preferred_languages, "firstObject")
        c_str = objc.msg_send(preferred_language, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str)


def test_ns_user_defaults(emu_ios, objc):
    with objc.autorelease_pool():
        user_defaults = objc.msg_send("NSUserDefaults", "standardUserDefaults")
        assert user_defaults

        key = pyobj2nsobj(emu_ios, "AppleLocale")

        apple_locale = objc.msg_send(user_defaults, "stringForKey:", key)
        c_str = objc.msg_send(apple_locale, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str)


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
        c_str = objc.msg_send(date_str, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str)

        date = objc.msg_send(date_formatter, "dateFromString:", date_str)
        assert date


def test_ns_time_zone(emu_ios, objc):
    with objc.autorelease_pool():
        time_zone = objc.msg_send("NSTimeZone", "defaultTimeZone")
        assert time_zone

        name = objc.msg_send(time_zone, "name")
        c_str = objc.msg_send(name, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str)

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
        c_str = objc.msg_send(bundle_path, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str)

        executable_path = objc.msg_send(main_bundle, "executablePath")
        c_str = objc.msg_send(executable_path, "cStringUsingEncoding:", 4)
        assert emu_ios.read_string(c_str)

        info_dictionary = objc.msg_send(main_bundle, "infoDictionary")
        assert info_dictionary
