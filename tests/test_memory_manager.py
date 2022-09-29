def test_alloc(arm64_emu):
    for n in range(1, 17):
        buffer = arm64_emu.memory_manager.alloc(2**n)
        arm64_emu.read_bytes(buffer, 2**n)


def test_free(arm64_emu):
    buffer = arm64_emu.memory_manager.alloc(1024)
    arm64_emu.memory_manager.free(buffer)
