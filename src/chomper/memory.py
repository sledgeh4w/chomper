from typing import List

from unicorn import Uc

from .structs import MemoryPool
from .utils import aligned


class MemoryManager:
    """Provide memory management on Unicorn.

    Each mapped memory is treated as a pool, and each pool contains one or more
    blocks of equal size. When allocating, it will first iterate pools to find
    one with enough block size, and then return an unused block. If the requested
    size is greater than `minimum_pool_size`, it will create a poll with only
    one block and enough size.

    Args:
        uc: The Unicorn instance.
        address: Base address of mapped memory.
        minimum_pool_size: Minimum size of pool.
    """

    def __init__(self, uc: Uc, address: int, minimum_pool_size: int):
        self.uc = uc
        self.address = address
        self.minimum_pool_size = minimum_pool_size

        self.pools: List[MemoryPool] = []

        self.init_pools()

    def create_pool(self, block_size: int) -> MemoryPool:
        """Create a pool."""
        if block_size <= self.minimum_pool_size:
            pool = MemoryPool(
                address=self.address,
                size=self.minimum_pool_size,
                blocks=[0 for _ in range(self.minimum_pool_size // block_size)],
            )

        else:
            pool = MemoryPool(address=self.address, size=block_size, blocks=[0])

        self.uc.mem_map(pool.address, pool.size)
        self.address += pool.size

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
