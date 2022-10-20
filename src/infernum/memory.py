from typing import List

from unicorn import Uc

from .const import MINIMUM_POOL_SIZE
from .structs import MemoryPool
from .utils import aligned


class MemoryManager:
    """Provide memory management on Unicorn.

    Each mapped memory is treated as a pool, and each pool contains one or more
    blocks of equal size. When allocating, it will first iterate pools to find
    one with enough block size, and then return an unused block. If the requested
    size is greater than ``minimum_pool_size``, it will create a poll with only
    one block and enough size.

    Args:
        uc: The Unicorn object.
        heap_address: Base address of mapped memory.
    """

    def __init__(self, uc: Uc, heap_address: int):
        self.uc = uc
        self.heap_address = heap_address

        self.minimum_pool_size = MINIMUM_POOL_SIZE
        self.pools: List[MemoryPool] = []

        self.init_pools()

    def create_pool(self, block_size: int) -> MemoryPool:
        """Create a pool."""
        if block_size <= self.minimum_pool_size:
            pool = MemoryPool(
                address=self.heap_address,
                size=self.minimum_pool_size,
                blocks=[0 for _ in range(self.minimum_pool_size // block_size)],
            )

        else:
            pool = MemoryPool(address=self.heap_address, size=block_size, blocks=[0])

        self.uc.mem_map(pool.address, pool.size)
        self.heap_address += pool.size

        return pool

    def init_pools(self):
        """Initialize pools.

        At the begging, some pools with different block sizes will be created.
        """
        block_sizes = [8 * 2**i for i in range(10)]

        for block_size in block_sizes:
            self.pools.append(self.create_pool(block_size))

    def alloc(self, size: int) -> int:
        """Alloc memory."""
        if size > self.minimum_pool_size:
            block_size = aligned(size, 1024)

        else:
            block_size = 8
            while block_size < size:
                block_size *= 2

        for pool in self.pools:
            if pool.block_size == block_size:
                try:
                    index = pool.blocks.index(0)
                    pool.blocks[index] = 1
                    return pool.address + index * pool.block_size

                except ValueError:
                    continue

        pool = self.create_pool(block_size)
        pool.blocks[0] = 1

        return pool.address

    def free(self, address: int):
        """Free memory."""
        for pool in self.pools:
            if pool.address <= address < pool.address + pool.size:
                index = (address - pool.address) // pool.block_size
                pool.blocks[index] = 0
