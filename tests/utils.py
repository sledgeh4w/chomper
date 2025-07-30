from contextlib import contextmanager


@contextmanager
def alloc_variables(emu, *args):
    buf_list = []

    for arg in args:
        if isinstance(arg, int):
            buf = emu.create_buffer(arg)
        elif isinstance(arg, str):
            buf = emu.create_string(arg)
        elif isinstance(arg, bytes):
            buf = emu.create_buffer(len(arg))
            emu.write_bytes(buf, arg)
        else:
            raise ValueError("Unsupported value type")
        buf_list.append(buf)

    try:
        yield buf_list
    finally:
        for buf in buf_list:
            emu.free(buf)
