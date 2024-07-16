def test_ns_string(emu_ios, objc):
    with objc.autorelease_pool():
        string = objc.msg_send("NSString", "stringWithUTF8String:", "chomper")

        assert string


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
        string = objc.msg_send(
            "NSString", "stringWithUTF8String:", "https://google.com"
        )

        url = objc.msg_send("NSURL", "alloc")
        objc.msg_send(url, "initWithString:", string)

        assert url


def test_ns_request(emu_ios, objc):
    with objc.autorelease_pool():
        string = objc.msg_send(
            "NSString", "stringWithUTF8String:", "https://google.com"
        )

        url = objc.msg_send("NSURL", "alloc")
        objc.msg_send(url, "initWithString:", string)

        request = objc.msg_send("NSMutableURLRequest", "requestWithURL:", url)

        assert request


def test_ns_locale(emu_ios, objc):
    with objc.autorelease_pool():
        preferred_languages = objc.msg_send("NSLocale", "preferredLanguages")

        assert preferred_languages

        preferred_language = objc.msg_send(preferred_languages, "firstObject")
        str_ptr = objc.msg_send(preferred_language, "cStringUsingEncoding:", 4)

        assert len(emu_ios.read_string(str_ptr)) > 0


def test_ns_user_defaults(emu_ios, objc):
    with objc.autorelease_pool():
        user_defaults = objc.msg_send("NSUserDefaults", "standardUserDefaults")

        assert user_defaults

        key = objc.msg_send("NSString", "stringWithUTF8String:", "AppleLocale")

        apple_locale = objc.msg_send(user_defaults, "stringForKey:", key)
        str_ptr = objc.msg_send(apple_locale, "cStringUsingEncoding:", 4)

        assert len(emu_ios.read_string(str_ptr)) > 0
