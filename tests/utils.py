from contextlib import contextmanager


@contextmanager
def multi_alloc_mem(emu, *args):
    mem_ptrs = []

    for arg in args:
        if isinstance(arg, int):
            mem_ptr = emu.create_buffer(arg)
        elif isinstance(arg, str):
            mem_ptr = emu.create_string(arg)
        elif isinstance(arg, bytes):
            mem_ptr = emu.create_buffer(len(arg))
            emu.write_bytes(mem_ptr, arg)
        else:
            raise ValueError("Unsupported value type")
        mem_ptrs.append(mem_ptr)

    try:
        yield mem_ptrs
    finally:
        for mem_ptr in mem_ptrs:
            emu.free(mem_ptr)
