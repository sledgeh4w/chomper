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
        str_ptr = objc.msg_send(string, "cStringUsingEncoding:", 4)

        assert emu_ios.read_string(str_ptr) == sample_str

        objc.msg_send(string, "appendString:", pyobj2nsobj(emu_ios, sample_str))
        str_ptr = objc.msg_send(string, "cStringUsingEncoding:", 4)

        assert emu_ios.read_string(str_ptr) == sample_str * 2


def test_ns_array(emu_ios, objc):
    with objc.autorelease_pool():
        array = objc.msg_send("NSMutableArray", "array")

        assert array

        string = objc.msg_send("NSString", "stringWithUTF8String:", "chomper")
        objc.msg_send(array, "addObject:", string)


def test_ns_dictionary(emu_ios, objc):
    with objc.autorelease_pool():
        dictionary = objc.msg_send("NSMutableDictionary", "dictionary")

        assert dictionary

        string = objc.msg_send("NSString", "stringWithUTF8String:", "chomper")
        objc.msg_send(dictionary, "setObject:forKey:", string, string)


def test_ns_data(emu_ios, objc):
    with objc.autorelease_pool():
        data_bytes = b"chomper"

        buffer = emu_ios.create_buffer(len(data_bytes))
        emu_ios.write_bytes(buffer, data_bytes)

        data = objc.msg_send("NSData", "dataWithBytes:length:", buffer, len(data_bytes))

        assert data


def test_ns_data_with_large_size(emu_ios, objc):
    """When the size of `NSData` exceeds 64k, `vm_allocate` will be called."""
    with objc.autorelease_pool():
        data_bytes = bytes(1024 * 64)

        buffer = emu_ios.create_buffer(len(data_bytes))
        emu_ios.write_bytes(buffer, data_bytes)

        data = objc.msg_send("NSData", "dataWithBytes:length:", buffer, len(data_bytes))

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
        str_ptr = objc.msg_send(preferred_language, "cStringUsingEncoding:", 4)

        assert len(emu_ios.read_string(str_ptr))


def test_ns_user_defaults(emu_ios, objc):
    with objc.autorelease_pool():
        user_defaults = objc.msg_send("NSUserDefaults", "standardUserDefaults")

        assert user_defaults

        key = objc.msg_send("NSString", "stringWithUTF8String:", "AppleLocale")

        apple_locale = objc.msg_send(user_defaults, "stringForKey:", key)
        str_ptr = objc.msg_send(apple_locale, "cStringUsingEncoding:", 4)

        assert len(emu_ios.read_string(str_ptr))


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
        str_ptr = objc.msg_send(date_str, "cStringUsingEncoding:", 4)

        assert len(emu_ios.read_string(str_ptr))

        date = objc.msg_send(date_formatter, "dateFromString:", date_str)

        assert date


def test_ns_time_zone(emu_ios, objc):
    with objc.autorelease_pool():
        time_zone = objc.msg_send("NSTimeZone", "defaultTimeZone")

        name = objc.msg_send(time_zone, "name")
        str_ptr = objc.msg_send(name, "cStringUsingEncoding:", 4)

        assert len(emu_ios.read_string(str_ptr))

        name_shanghai = pyobj2nsobj(emu_ios, "Asia/Shanghai")
        time_zone_shanghai = objc.msg_send(
            "NSTimeZone", "timeZoneWithName:", name_shanghai
        )

        assert time_zone_shanghai

        objc.msg_send("NSTimeZone", "setDefaultTimeZone:", time_zone_shanghai)
