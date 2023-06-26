def test_alloc(emu_arm64):
    for n in range(1, 17):
        buffer = emu_arm64.alloc(2**n)
        emu_arm64.read_bytes(buffer, 2**n)


def test_free(emu_arm64):
    buffer = emu_arm64.alloc(1024)
    emu_arm64.free(buffer)
