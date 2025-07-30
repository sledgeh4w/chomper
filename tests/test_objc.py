from chomper.objc import ObjcObject


def test_create_ns_objs(emu_ios, objc):
    with objc.autorelease_pool():
        result = objc.create_ns_number(1)
        assert result

        result = objc.create_ns_string("chomper")
        assert result

        result = objc.create_ns_data(b"chomper")
        assert result

        result = objc.create_ns_array([1, 2, 3])
        assert result

        result = objc.create_ns_dictionary(
            {
                "name": "chomper",
            },
        )
        assert result


def test_create_cf_objs(emu_ios, objc):
    with objc.autorelease_pool():
        result = objc.create_cf_number(1)
        assert result

        result = objc.create_cf_string("chomper")
        assert result

        result = objc.create_cf_data(b"chomper")
        assert result

        result = objc.create_cf_array([1, 2, 3])
        assert result

        result = objc.create_cf_dictionary(
            {
                "name": "chomper",
            },
        )
        assert result


def test_msg_send(emu_ios, objc):
    with objc.autorelease_pool():
        ns_mutable_dictionary_class = objc.find_class("NSMutableDictionary")

        dictionary = ns_mutable_dictionary_class.call_method("dictionary")
        assert isinstance(dictionary, ObjcObject)

        retval = dictionary.call_method(
            "setObject:forKey:",
            objc.create_ns_string("key"),
            objc.create_ns_string("value"),
        )
        assert retval == 0

        count = dictionary.call_method("count")
        assert isinstance(count, int)


def test_get_variable(emu_ios, objc):
    with objc.autorelease_pool():
        ns_error_class = objc.find_class("NSError")

        domain = objc.create_ns_string("com.sledgeh4w.chomper")
        code = 1000

        error = ns_error_class.call_method(
            "errorWithDomain:code:userInfo:", domain, code, 0
        )

        result = error.get_variable("_domain")
        assert result == domain

        result = error.get_variable("_code")
        assert result == code


def test_get_class_method(emu_ios, objc):
    with objc.autorelease_pool():
        ns_string_class = objc.find_class("NSString")

        sel_name = "stringWithUTF8String:"
        symbol_name = "+[NSString stringWithUTF8String:]"

        method = ns_string_class.get_class_method(sel_name)
        assert method and method.name == sel_name

        symbol = emu_ios.find_symbol(symbol_name)
        assert method.implementation == symbol.address


def test_get_instance_method(emu_ios, objc):
    with objc.autorelease_pool():
        ns_string_class = objc.find_class("NSString")

        sel_name = "length"
        symbol_name = "-[NSString length]"

        method = ns_string_class.get_instance_method(sel_name)
        assert method and method.name == sel_name

        symbol = emu_ios.find_symbol(symbol_name)
        assert method.implementation == symbol.address
